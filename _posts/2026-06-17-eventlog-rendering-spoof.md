---
title: "Lying to the Analyst: Event Log Rendering-Metadata Spoofing"
date: 2026-06-17 16:00:00 +0000
categories: [Windows Internals, Offensive Research]
tags: [event-log, defense-evasion, dfir, wevtapi, siem, windows-internals]
toc: true
---

## 1. Background: How Windows Turns a Number into a Sentence

An event in the Windows event log is not a sentence. On disk, in the EVTX, an event is a numeric `EventID`, a publisher GUID, a set of binary substitution values, and some metadata (level, keywords, timestamps). The human-readable line an analyst reads in Event Viewer, *"An operation was performed on an object"*, does not exist in the EVTX at all. It is **rendered on demand** by joining the numeric event to a **message template** that lives in a resource DLL on the box.

That join is driven entirely by the registry. Each publisher registers, under `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Publishers\{GUID}`, a small set of file-path values that tell the rendering code which DLLs hold the templates:

| Value | Holds |
| --- | --- |
| `ResourceFileName` | event templates (WEVT_TEMPLATE) and, for legacy sources, the message table |
| `MessageFileName` | the message-string table |
| `ParameterFileName` | `%%NNNN` parameter expansions (access-right names, object types, etc.) |

For the Security channel, the publisher is **Microsoft-Windows-Security-Auditing**, GUID `{54849625-5478-4994-A5BA-3E3B0328C30D}`, and on a stock Windows 11 26200 box those values point at:

```
ResourceFileName  = C:\Windows\System32\adtschema.dll
MessageFileName   = C:\Windows\System32\adtschema.dll
ParameterFileName = C:\Windows\System32\msobjs.dll
```

So when you open a Security 4662 in Event Viewer, the renderer reads the numeric event from the EVTX, looks up the publisher GUID, opens `adtschema.dll` to get the template for ID 4662, opens `msobjs.dll` to expand the `%%NNNN` access-mask codes into words like *WriteDACL*, and stitches the final string. **The sentence is a function of the registry pointer, not of the log file.**

That is the seam. This post is about repointing those values at an attacker-controlled resource DLL so the renderer produces a *false* sentence for a *real* event, without altering a single byte of the EVTX.

The ceiling, up front: this needs administrator rights, runs no code in any process, and is not a boundary Microsoft defends, so there is no CVE here. It is a deception primitive, not an exploit. What makes it worth a writeup is that the deception is precise, survives EVTX integrity checks, and reaches whatever consumes the rendered text, your SIEM included.

It is also a post about three things that look like they should work and do **not**, and I am going to spend as much ink on the falsified claims as on the working one, because the honest boundary is what makes this a usable finding.

## 2. Four Layers of "Spoofing" and Which One This Is

When someone asks *"can a 4662 be spoofed?"* the question is underspecified, because there are four distinct layers at which you could intervene, with wildly different feasibility:

| # | Layer | What it controls | Feasible on 26200? |
| --- | --- | --- | --- |
| 1 | **Generation** (kernel SRM → LSASS audit) | the numeric `EventID` written to the EVTX | **No**, lives behind the PPL wall (Section 8) |
| 2 | **Rendering** (publisher metadata → resource DLL) | the human-readable Message the analyst/SIEM sees | **Yes**, this post |
| 3 | **Forging** (ETW `EventWrite` as a provider) | injecting fake events into non-Security channels | Yes, for non-protected channels |
| 4 | **Suppression / EVTX edit** | removing or altering stored records | Known (auditpol/SACL; SYSTEM service handle) |

This post is **layer 2 only**, fully reverse-engineered, with two honest boundary results bolted on so it cannot be waved away:

- Layer 1 is a hard wall (the numeric ID is assigned inside PPL-protected `lsass.exe`; Section 8).
- Layer 2 gives you **no code execution**: not in the analyst's process, not in the EventLog service. It is a pure deception primitive (Sections 5 and 6).

If you came here hoping "open the Security log, get popped," set that expectation down now. That vector is falsified in Section 4, with the import table to prove it. What you get instead is the ability to make the log *lie* to whoever reads the rendered text, which, given how SIEMs and analysts actually consume logs, is its own problem.

## 3. The Tamperable Surface: Admin-Writable Render Metadata

The whole technique rests on one ACL fact.

The publisher key for Security-Auditing grants:

```
BUILTIN\Administrators   FullControl
NT AUTHORITY\SYSTEM      FullControl
```

`BUILTIN\Administrators` has **FullControl** over the render-metadata key. That means an administrator, or anything that has just won a UAC bypass, can rewrite `ResourceFileName`, `MessageFileName`, and `ParameterFileName` with a plain `RegSetValueEx`. **No TrustedInstaller required.**

There is a subtlety worth stating precisely, because it is the difference between "needs TI" and "needs only admin":

- The *files* `adtschema.dll` and `msobjs.dll` are owned by `NT SERVICE\TrustedInstaller`. Overwriting those files on disk would need TI.
- But you are not overwriting the files. You are **repointing the registry value** at *your own* DLL sitting somewhere else (say `C:\ProgramData\test.dll`). Rewriting the value only needs write access to the key, and Administrators has it.

So the practical vector sidesteps the file ownership entirely. You never touch a TI-owned file, you change where the renderer looks.

And it is not a Security-channel quirk. I sampled the render-metadata ACLs across publishers and **60 of 60 sampled publishers grant Administrators write access to their `ResourceFileName`/`MessageFileName`/`ParameterFileName`**. So the *writable-metadata precondition* is general across essentially the entire Windows telemetry surface (DNS, PowerShell, Sysmon-adjacent providers, anything), not Security-only. The repoint-and-spoof itself then reproduces wherever an event's description resolves through an `RT_MESSAGETABLE`, which is the common case; a publisher that renders purely from a `WEVT_TEMPLATE` with no message-table string would need that template rebuilt, not just a string patched. Security 4662 is just the most legible target to demonstrate it on.

## 4. The Render Pipeline, Reverse-Engineered (wevtapi.dll 26200)

Before trusting that this is a *rendering* spoof and not a *code-exec* primitive, you have to know exactly where the resource DLL gets loaded and by whom. So I walked the render path in `wevtapi.dll` (the client-side eventing API that `eventvwr.exe`, `Get-WinEvent`, and most SIEM agents call) on Windows 11 26200.

The call chain that formats an event's message string:

```
EvtFormatMessage                         (RVA 0xa100)
  └─ EventRendering::MessageRender        (RVA 0xb728)
       └─ GetRenderedMessageFromService   (RVA 0xd9d0)
            └─ NdrClientCall3(pProxyInfo, procnum 9, …)   ← RPC to the EventLog service
```

The relevant RVAs in `wevtapi.dll` 26200:

| Symbol | RVA |
| --- | --- |
| `EvtFormatMessage` | `0xa100` |
| `EvtOpenPublisherMetadata` | `0x17b0` |
| `EventRendering::MessageRender` | `0xb728` |
| `GetRenderedMessageFromService` (→ `NdrClientCall3`) | `0xd9d0` |
| `PublisherMetadataObject::ctor` | `0x13ec4` |
| `GetCachedDescString` / `SetCachedDescString` | `0xdd54` / `0xe244` |

The single most important observation in this whole post is what is **missing** from `wevtapi.dll`'s import table:

> `wevtapi.dll` imports **no** `LoadLibrary` / `LoadLibraryEx`. The only module-related imports are `GetModuleHandleW`, `GetModuleHandleExA`, `GetModuleHandleExW`, `GetProcAddress`, and `GetModuleFileNameA`. Statically, nothing here maps a module on its own, and the render path goes over RPC instead (next paragraph).

It *does* import the full RPC client surface: `NdrClientCall3`, `RpcBindingFromStringBindingW`, `RpcBindingSetAuthInfoExW`, and friends. So `GetRenderedMessageFromService` does exactly what its name says: it bundles the request and ships it over RPC to the **EventLog service**, and the service does the template resolution. There are two `NdrClientCall3` sites in the function: procnum **9** when it is handed an `EvtOpenPublisherMetadata` handle (the path the Section 7 4624 render takes, and the one that caches its result via `SetCachedDescString`), and procnum **0xA** (decimal 10) as the no-metadata fallback that resolves from the event's own publisher identity. Either way the resolution happens service-side. There is also a client-side cache (`PublisherMetadataObject::GetCachedDescString` / `SetCachedDescString`), but it is populated *from the service's rendered result*, and the client never resolves a resource DLL itself.

This kills the first over-claim cleanly. The analyst's process (`eventvwr.exe`, the PowerShell running `Get-WinEvent`, the SIEM agent) **cannot be made to execute attacker code by rendering an event**, because the DLL that would carry that code is never loaded in that process. It is loaded across an RPC boundary, in the service. The "view-the-log-get-popped" vector is **falsified**, and the proof is the RPC-delegated render path, corroborated by the missing `LoadLibrary` import, not a hunch.

## 5. Where the Resource DLL Actually Loads, and Why It's Still Not Code Exec

So the load happens in the EventLog service (`wevtsvc.dll`). The obvious next worry: if the *service* does a full `LoadLibrary` of an attacker-controlled `ResourceFileName`, that is code execution as **LOCAL SERVICE** inside `svchost`, which would be a far bigger finding than a rendering spoof.

It does not. I pulled `wevtsvc.dll` 26200 into IDA and found the load site: `LibraryCache::LoadLibraryExW` at RVA `0xab530`. Its single underlying call is:

```c
Library = LoadLibraryExW(ResourceFileName, NULL, 0x60);
```

The flags are the whole story:

```
0x60 = LOAD_LIBRARY_AS_IMAGE_RESOURCE      (0x20)
     | LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE  (0x40)
```

That combination maps the DLL **as a pure resource/data image**. No `DllMain` runs. No imports are resolved. No `TLS` callbacks fire. The PE is mapped so the loader can read its `.rsrc` and nothing else. The service then pulls the templates and parameter strings out of it with `FindResourceExW` → `LoadResource` → `LockResource`. The attacker DLL is consumed strictly as a **resource container**, a bag of templates, never as executable code.

So code execution is falsified on **both** sides of the RPC:

| Side | Process | Why no code runs |
| --- | --- | --- |
| Consumer | `eventvwr` / `Get-WinEvent` / SIEM agent | `wevtapi.dll` imports no `LoadLibrary`, render is RPC-delegated |
| Service | EventLog (`wevtsvc.dll` in `svchost`) | loads `ResourceFileName` with flags `0x60` = data-only, no `DllMain` |

What survives both falsifications is the deception itself:

- The EventLog service renders using the **attacker-controlled** `ResourceFileName` / `ParameterFileName` (read as resources).
- So the description and parameter strings returned to the analyst/SIEM are attacker-controlled.
- The EVTX numeric `EventID` and the binary substitution data are **untouched**.

That is the entire finding, stated honestly: **you do not run code, and you do not change what the log *is*; you change what the analyst *sees* it as.**

## 6. The Mechanism in One Picture

![Repoint the publisher resource pointer at an attacker DLL, restart the EventLog service, and the analyst renders an attacker-supplied template for a real, byte-for-byte unchanged on-disk event](/assets/img/posts/eventlog-rendering-spoof-mechanism.png)

The EVTX bytes never move. Only the registry pointer and a DLL on some other path changed. The renderer faithfully does its job, against attacker-supplied templates.

## 7. Runtime PoC: The Log Lies, On the Record

I proved the mechanism end-to-end on Windows 11 Pro 26200 on **2026-06-02**, using a self-contained **legacy Application source** rather than the Security channel, for one practical reason: a legacy source lets me carry the whole proof in two tiny message-table DLLs and a PowerShell script, with no dependence on the protected Security pipeline. The mechanism is identical; the one open question was the payload format for a modern manifest publisher, which I work out below, and it turned out simpler than I assumed.

The setup: a legacy source `EvtSpoofDemo`, and two resource DLLs (`real.dll` and `spoof.dll`), **both** defining the same message id `0x400003E8` (low 16 bits = displayed Event ID **1000**, the `.mc` header that sets `Severity=Informational` and the language block is elided in the snippets below). The two message tables differ only in text:

`real.mc`:

```
MessageId=1000
SymbolicName=MSG_OP
Language=English
SECURITY ALERT: %1 performed a SENSITIVE operation (%2) on object %3.
.
```

`spoof.mc`:

```
MessageId=1000
SymbolicName=MSG_OP
Language=English
Information: scheduled time synchronization completed successfully.
.
```

The PoC registers the source pointing `EventMessageFile` at `real.dll`, writes **one** event with insert strings `("DESKTOP\attacker", "WriteDACL/AllAccess", "lsass.exe")`, renders it, then repoints `EventMessageFile` at `spoof.dll`, restarts the EventLog service to flush the metadata cache, and re-renders **the same on-disk event**:

```
[3] Render with the REAL message file:
  [BEFORE (real.dll)]
     Rendered Message : SECURITY ALERT: DESKTOP\attacker performed a SENSITIVE operation (WriteDACL/AllAccess) on object lsass.exe.
     .Id (displayed)  : 1000
     EVTX Qualifiers  : 16384
[4] SPOOF: repoint EventMessageFile -> spoof.dll (Administrators-writable; no EVTX change)
[5] Re-render the SAME on-disk event with the spoofed message file:
  [AFTER (spoof.dll)]
     Rendered Message : Information: scheduled time synchronization completed successfully.
     .Id (displayed)  : 1000
     EVTX Qualifiers  : 16384
```

Same numeric EventID (1000), same Qualifiers (16384), same on-disk record, but a completely different rendered Message. An analyst or a SIEM keying on the description now sees *routine time synchronization* for an event whose raw substitution data is a privilege operation on `lsass.exe`.

The flush mechanism is mundane and important: `Restart-Service EventLog` is enough to make the service honor the new pointer. No reboot. The cache (`PublisherMetadataObject::SetCachedDescString` on the client; the service's own `LibraryCache`) is the only thing keeping the old string alive, and a service restart clears it.

### From a legacy source to a real Security event (4624), demonstrated

I first wrote this section as a promissory note: the legacy run is the clean proof, the Security port is mechanical, author a WEVT_TEMPLATE and you are done. Then I went and did the port on a real Security event, and two things came out of it that are worth more than the promise was. It works end to end against a live Security-Auditing event, verified through the exact API Event Viewer uses. And the port is *not* what I claimed it was, which is the interesting part.

I picked **4624** (*"An account was successfully logged on"*) rather than 4662, because the most legible lie this primitive can tell is *a different user logged in*. The New Logon block of a 4624 carries an `Account Name`, if I can make a real logon render under a name of my choosing while the EVTX still holds the true account, that is the whole thesis in one screenshot.

**You do not need to author a WEVT_TEMPLATE.** That was the wrong assumption. The description string for a manifest event is a *message reference*: the compiled manifest points at a message id, and that id resolves into a plain `RT_MESSAGETABLE` in the resource DLL, the same classic message table a legacy source uses. So to change the rendered description I do not rebuild the template at all. I leave the WEVT_TEMPLATE alone and patch the **message-table string** it already points at. The 4624 text lives in `adtschema.dll`'s message table, and in its `en-US\adtschema.dll.mui`, which on an en-US box is where the localized string actually resolves; both the base table and the MUI can carry the string and which one the loader honors depends on locale, so I patch both in a *staged copy* and repoint the publisher metadata at that copy, never touching the TI-owned originals in System32. In the message-table string itself the New Logon account name is insertion token `%6` and the Subject account name above it is `%2` (confirmed against the table, not the rendered layout, which reorders the blocks so Logon Type sits between them). Replace `%6` with a literal and every 4624 renders that literal as the account that logged on.

**The one non-mechanical thing: Security events are versioned, and the version is in the message id.** This is what "straightforward port" was hiding. The same 4624 text is not stored once. It is stored *four times* in the message table: an un-versioned base id `0x1210` plus three version-stamped ids `0xb0001210`, `0xb0011210`, and `0xb0021210`. The versioned ids follow `0xB0000000 | (version << 16) | 0x1210`, so the `0xb00v` high word stamps the event **version** (v0, v1, v2) while the low word keeps the event id, and each copy has a slightly different field layout. The base `0x1210` has no version word at all, which is why it alone lacks the `0xb`: it is the un-versioned default string, not version 0 (v0 is `0xb0001210`). Windows 11 26200 emits 4624 at **version 2**, so the renderer resolves `0xb0021210`. My first patch hit only the first copy (`0x1210`), and the live event still rendered the real account, because the event I was staring at resolved to v2, which I had not touched. The fix is to patch *every* copy. If you take one thing from this section into your own work: when you spoof a Security event's description, enumerate **all** message-table ids whose text matches and patch all of them, because the one the box actually emits is the versioned id, not the base.

The patch is length-safe. Each message-table string is rewritten in place and padded back to its original byte length, reusing the existing null terminator, so neither the message table nor the PE resource directory shifts. Two operational details that cost me time and are easy to miss: the EventLog service runs as `LOCAL SERVICE`, so the staged copy has to be readable by it (`icacls <dir> /grant *S-1-1-0:(OI)(CI)(RX)`, Everyone read+execute, otherwise rendering silently falls back to *"The description for Event ID ... cannot be found"*); and the `en-US` MUI has to sit next to the DLL or the localized lookup misses. Then repoint `ResourceFileName` and `MessageFileName` at the patched copy, `Restart-Service EventLog`, and it is armed.

I did not eyeball Event Viewer and call it done. I drove the exact `wevtapi` render that the General tab uses, against a 4624 already sitting in the Security log, reading the now-repointed publisher metadata:

```
EvtQuery(Security, "*[System[(EventID=4624)]]")
  -> EvtNext                          (a real, already-logged 4624)
  -> EvtOpenPublisherMetadata("Microsoft-Windows-Security-Auditing")
  -> EvtFormatMessage(EvtFormatMessageEvent)
```

Rendered result:

```
An account was successfully logged on.
   ...
   Account Name:    DESKTOP-N604E83$     <- Subject   (%2, the REAL caller, untouched)
   Account Name:    POC                  <- New Logon (%6, SPOOFED)
   ...
```

And here is the same event in Event Viewer's own General tab, the spoofed publisher metadata resolving live:

![Event Viewer General tab for a real Security 4624. The Subject Account Name is the true computer account DESKTOP-N604E83$, while the New Logon Account Name renders the attacker-chosen literal POC. The on-disk record is unchanged; only the publisher resource pointer was repointed.](/assets/img/posts/eventlog-rendering-spoof-4624.png)
_Event Viewer, General tab, a real Security 4624. The Subject Account Name is the true `DESKTOP-N604E83$`; the New Logon Account Name reads `POC`. Nothing in the EVTX was touched, only the publisher resource pointer._

Same on-disk record, same numeric 4624, and the Details/XML tab still carries the true `TargetUserName`. The General tab, which is what triage actually reads, says a principal named `POC` logged on. That is a demonstrated spoof of a real Security event, through the renderer the analyst's own tools call, not a port I am asking you to take on faith.

One honesty tax specific to this approach: because the spoof is a literal substituted for the `%6` token, *every* 4624 renders `POC` in the New Logon name while armed. It is a blanket rewrite of the rendered field, not a per-event forgery. Making one chosen logon lie while the rest render truthfully would require conditioning on the substitution data, which the message-table format does not let you do. For an anti-forensics primitive that wants to drown a specific logon in noise, or make the logon history unreadable as a set of names, the blanket rewrite is usually what you wanted anyway.

## 8. The Wall: You Cannot Change the Numeric ID (Vector 1)

The strongest version of the attack would be to change the number itself: make the generator emit `1000` instead of `4662`, so even a raw-XML forwarder is fooled. I chased that (layer 1) and hit a hard wall, and the writeup is more honest for naming it.

RE of `lsasrv.dll` 26200 plus runtime checks settle it:

- The audit-event **generators** (`LsapAdtGenerateObjectOperationAuditEvent` for 4662 object-operation, `LsapAdtGenerateLsaAuditEvent`, `LsapAdtGenerateDomainPolicyChangeAuditEvent`, and the rest) are all **delay-load imports from `LSAADT.dll`** (`__imp_load_LsapAdtGenerate*`).
- The write API `LsapAdtWriteLog` is likewise **imported from module `LSAADT`**.
- So the numeric Event-ID assignment and audit-record construction live in **`LSAADT.dll`, loaded inside `lsass.exe`**.

And on this box, at runtime:

```
RunAsPPL     = 2
RunAsPPLBoot = 2
```

`lsass.exe` is **PPL-protected**. `OpenProcess(PROCESS_VM_READ)` against it is **DENIED (error 5)**. I could not even read it, let alone patch the code/data that stamps the `4662`.

So changing the numeric ID at generation requires modifying code or data inside PPL-protected `lsass.exe`, which (a) loads only Microsoft-signed DLLs under Code Integrity, and (b) exposes no memory writable from userland or even admin. This is the **same protection class as credential dumping**: it needs a kernel or PPL bypass, and it is out of reach for a userland/admin attacker. Vector 1 is a real wall.

That wall is exactly why layer 2 matters. **You cannot change what the log *is* (PPL-protected generation), but you can change what the analyst and SIEM *see* it as (Administrators-writable rendering metadata).** That asymmetry is the thesis.

## 9. What This Defeats, and What It Does NOT

Being precise here is the point of the whole finding, so I will draw the line in both directions.

**Defeats:**

- **EVTX file-integrity hashing / WORM archival of raw bytes.** The on-disk event is byte-for-byte unchanged; only the registry pointer and an out-of-tree DLL changed. Hashing the EVTX catches nothing.
- **Message-based SIEM rules.** Any rule, correlation, or alert that keys on the rendered `Message` string (`Get-WinEvent | Where Message -match …`, WEF/WEC pipelines that forward rendered descriptions, log shippers that grab the formatted text) consumes the attacker-controlled string.
- **Human triage.** The Event Viewer "General" tab and every console that shows the rendered description show the lie. An analyst skimming descriptions sees routine noise.
- **Generality of the precondition.** 60/60 sampled publishers grant Administrators write to their render metadata, so the *repointability* is a property of the telemetry surface, not a Security-channel quirk. The string-level spoof then reproduces wherever the description resolves through an `RT_MESSAGETABLE` (the common case); a pure-`WEVT_TEMPLATE` publisher with no message-table string would need its template rebuilt rather than a string patched.

**Does NOT defeat:**

- **Raw-XML / numeric-ID forwarding.** The `EventID` in the XML is still `4662`. A pipeline that forwards and alerts on the *numeric* ID (and the raw `EventData`), and renders downstream with its own trusted metadata, is **not** fooled. I am stating this plainly: if your detection keys on the number, this technique does not touch you.
- **Code execution.** It buys none: not in the analyst's process (Section 4), not in the service (Section 5). It is a deception primitive, full stop.
- **The numeric ID at generation.** PPL wall (Section 8). The stored `4662` stays `4662`.

The honest one-liner: this makes the **rendered story** of a real event a lie, while leaving the **numeric truth** in the EVTX intact. Whether that defeats *your* detection depends entirely on whether you read the story or the number.

## 10. Detection

The good news for defenders is that the action is narrow and rare in the wild.

| Indicator | Why it's suspicious | Telemetry |
| --- | --- | --- |
| `RegSetValue` to `HKLM\...\WINEVT\Publishers\*\(ResourceFileName \| MessageFileName \| ParameterFileName)` | Legitimately written only by installers; an interactive/runtime change is anomalous | Registry auditing (SACL) / EDR registry sink |
| A publisher resource path pointing **outside** `%SystemRoot%\System32` | Stock publishers all live in System32 | Registry value inspection / config baselining |
| A publisher resource path pointing at a **non-TI-owned** file | Stock resource DLLs are TrustedInstaller-owned | File-ownership check on the pointed path |
| `Restart-Service EventLog` / EventLog stop-start outside patching windows | Required to flush the metadata cache | Service-control (7035/7036) + process telemetry |
| Rendered `Message` diverging from an independent render of the same numeric ID | Direct evidence of the spoof | SIEM-side comparison |

The single highest-value control is the last one: **render at the SIEM from a trusted, pinned copy of the publisher metadata, and compare against the endpoint's rendered string.** Divergence is the spoof. Equivalently, **forward raw EVTX/XML (numeric `EventID` + `EventData`), never the endpoint-rendered `Message`**, which sidesteps the entire technique because you stop trusting the box's rendering at all.

Note one thing the renderer denies the attacker on the defense side: because `wevtapi` does the render over RPC and the service loads the DLL `0x60` data-only, there is **no `LoadLibrary` of the spoof DLL in the analyst's process** to catch; the load is in `svchost`, as a data file. So image-load telemetry on the analyst host will not flag the spoof DLL. Watch the **registry write** and the **service restart**, not an image load.

## 11. Mitigations

The honest starting point: this needs Administrator, and "an admin can tamper with the local machine" is not a boundary Microsoft commits to defending. An admin repointing their own box's logging metadata sits in the same non-boundary as clearing the log or stopping the EventLog service, so there is no MSRC-class bug here and no vendor patch to wait for. The controls that matter are defender-side, and they all reduce to one idea: stop trusting the endpoint's own rendering.

- **Forward raw, render trusted.** Forward the numeric `EventID` and the raw `EventData`, and render at a trusted collector with pinned publisher metadata (see Section 10). The box's rendering metadata never enters your detection path, which sidesteps the technique outright. This is the one control that actually defeats it.
- **Monitor the pointers.** Put an audit SACL on the `HKLM\...\WINEVT\Publishers\*` render-metadata values and alert on any write; installers write them, so a runtime change is the attack. Pair it with the divergence check from Section 10 (the endpoint's rendered string versus an independent render of the same numeric ID).

For completeness, not as an expectation: Microsoft *could* tighten the key so Administrators cannot repoint it, or make the service refuse a `ResourceFileName` that is not a Microsoft-signed binary under System32. I would not bank on either. The first is weak because an admin can take ownership of the key and re-grant write; the second would break every third-party publisher that legitimately ships its own resource DLL outside System32, Sysmon included. The defender-side controls above are the real answer, precisely because the registry pointer is not a boundary you can expect the platform to defend for you.

## 12. Conclusion

Windows event descriptions are computed, not stored. The number `4662` lives in the EVTX behind a PPL wall you cannot move; the sentence *"sensitive operation on lsass.exe"* lives behind an Administrators-writable registry pointer you can. Repoint that pointer at your own resource DLL, restart the EventLog service, and every consumer that reads the rendered description (Event Viewer, message-matching SIEM rules, human triage) reads your story instead of the real one, while the EVTX bytes and integrity hashes stay pristine.

I want to be equally clear about the ceiling. You get **no code execution** anywhere: `wevtapi.dll` imports no `LoadLibrary`, so the analyst's process is inert at render time. `wevtsvc.dll` loads the resource DLL with flags `0x60`, so the service treats it as a data file with no `DllMain`. And you **cannot change the number**: generation happens in `LSAADT.dll` inside PPL-protected `lsass.exe`, the same wall that stops credential dumping. A raw-XML, numeric-ID forwarding pipeline is untouched by this.

What is left is still a real primitive, and it is now demonstrated on a real Security event rather than argued by analogy: in the common case where detection and triage consume the *rendered message*, an admin-level attacker can make the security log narrate a lie about a real, on-disk, correctly-numbered event, and defeat both file-integrity hashing and message-based alerting in the process. The 4624 run in Section 7 makes a genuine logon render under an attacker-chosen account name through the same renderer the analyst's own tools call. The defensive lesson is one sentence: **forward the number, not the sentence, and render it somewhere you trust.**

---

## Attribution & Status

- All RVAs (`wevtapi.dll` and `wevtsvc.dll` 26200), the import-table observation (no `LoadLibrary` in `wevtapi`), the `0x60` load-flag at `wevtsvc!LibraryCache::LoadLibraryExW` `0xab530`, the two render RPC procnums in `GetRenderedMessageFromService` (`9` for the publisher-metadata path the demo uses, `0xA`/10 for the no-metadata fallback), and the LSASS/LSAADT generation findings were reverse-engineered on Windows 11 Pro 26200. The publisher GUID `{54849625-5478-4994-A5BA-3E3B0328C30D}` and the `adtschema.dll`/`msobjs.dll` mappings are the as-shipped 26200 values.
- **Proven (legacy source):** the end-to-end rendering spoof on a legacy Application source (2026-06-02), with the before/after rendered strings in Section 7 captured from that run; the Administrators=FullControl ACL on the publisher key; the 60/60 sampled-publisher repointability; the falsification of code execution on both the consumer and service sides; and the PPL wall on vector 1 (`OpenProcess(VM_READ)` on `lsass` denied, error 5, with `RunAsPPL=2`).
- **Proven (real Security event, 2026-06-08):** a spoofed **Security 4624**, demonstrated end to end on Windows 11 26200. The New Logon `Account Name` renders as an attacker-chosen literal (`POC`) while the Subject account, the numeric EventID, and the Details/XML `TargetUserName` stay real. Verified not by eyeballing Event Viewer but by driving the same `wevtapi` path it uses (`EvtQuery` → `EvtNext` → `EvtOpenPublisherMetadata("Microsoft-Windows-Security-Auditing")` → `EvtFormatMessage(EvtFormatMessageEvent)`) against a live 4624, reading the repointed publisher metadata. This also corrected the earlier assumption that a manifest port needs a hand-authored WEVT_TEMPLATE: the description resolves from the `RT_MESSAGETABLE` the template already references, so patching the message-table string in a staged copy of `adtschema.dll` and its `en-US` MUI, then repointing the publisher metadata at that copy, is sufficient. The non-obvious cost was event **versioning**: the same text lives at four message ids (`0x1210`, `0xb0001210`, `0xb0011210`, `0xb0021210`) and Windows 11 emits version 2 (`0xb0021210`), so all copies must be patched.
- **Not separately shown:** a spoofed **4662** specifically. It uses the identical message-table mechanism as the demonstrated 4624; I demonstrated 4624 because a spoofed logon account is the more legible result, and did not also screenshot 4662.
- **Falsified (and presented as such):** code execution in the analyst's `eventvwr`/`Get-WinEvent`/SIEM process; code execution in the EventLog service; and any change to the numeric `EventID` at generation.
