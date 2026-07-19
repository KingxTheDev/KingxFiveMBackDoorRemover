# Backdoor Scanner

A Windows desktop tool that scans a FiveM `resources` folder for obfuscated JavaScript backdoors and quarantines or deletes them. Built by Kingx Development.

## Why

FiveM scripts distributed as `.js` addons occasionally ship with hidden, obfuscated payloads that decode and `eval()` malicious code at runtime (data exfiltration, remote code execution, etc.). This tool scans every `.js` file under a folder tree and flags files matching known backdoor patterns, so they can be reviewed, quarantined, or removed before the server ever loads them.

## Detection

Each `.js` file is scored against a set of signals. A file is flagged once its score crosses a threshold:

- **Hidden file** - a `.js` file with the Windows hidden attribute, or a dotfile, is inherently suspicious.
- **`require('vm')`** - loading Node's `vm` module to execute dynamically decoded code. Practically never appears in legitimate FiveM resource scripts.
- **`vm.runInThisContext()`** - direct execution of decoded content in the current context.
- **`eval(decodeFn(payload, key))`** - a decoded payload fed straight into `eval()` as a bare function call. This exact shape (`eval(` immediately wrapping a function call with 1-2 plain identifier arguments) is the actual signature of the obfuscated-payload stubs this tool was built from, and it's not something legitimate code writes regardless of file size.
- **XOR decode loop** (`String.fromCharCode(...) ^ key`), **large numeric byte-array payloads**, and **heavy hex-escape strings** - supporting evidence only. Each is weighted low and none of them can flag a file on its own, since a large legitimate bundle (a built NUI `index.js`, a webpack `build.js`, etc.) can trip one of these by sheer size alone. They only matter stacked alongside one of the signals above.

The scoring is tuned from real backdoor samples found in the wild, not guesswork, but no automated scanner is perfect. Always review a flagged file before deciding to delete it.

## Features

- Recursive scan of an entire `resources` folder, skipping `node_modules`/`.git` and symlink cycles
- Live progress while scanning
- Right-click a detection to **Open File**, **Open File Location**, **Quarantine**, or **Delete Permanently**
- Bulk **Quarantine Selected** / **Delete Selected** across multiple detections
- Quarantine moves files into a `_quarantine` folder under the scanned root (nothing is deleted silently) and logs every move with a timestamp and reason
- Delete requires an explicit confirmation, since it's irreversible

## Requirements

- Windows 10/11
- [.NET 8 SDK](https://dotnet.microsoft.com/download/dotnet/8.0) to build

No other runtime dependency - this is a plain WPF app, no browser engine or WebView required.

## Build

```
dotnet build
```

Produces a normal framework-dependent build in `bin/Debug/net8.0-windows/`.

## Publish a single exe

```
dotnet publish -c Release
```

Output: `bin/Release/net8.0-windows/win-x64/publish/BackdoorScanner.exe` - a single self-contained executable, no other files required alongside it.

## Usage

1. Open the app and paste or browse to your FiveM `resources` folder.
2. Click **Scan**.
3. Review flagged files in the results list - right-click any row for options.
4. **Quarantine** to move a suspicious file aside (recoverable), or **Delete Permanently** to remove it for good.

## Disclaimer

This tool is provided for defensive security use on servers and files you own or are authorized to inspect. It flags suspicious patterns; it does not guarantee a file is malicious or that a clean scan means a server is safe. Always keep backups before deleting anything.

## Changelog

### 1.1.0

- Added a precise structural check for `eval(decodeFn(payload, key))` - catches backdoor stubs that `eval()` their decoded payload directly instead of going through `vm.runInThisContext()`.
- Fixed a false-negative from the 1.0 release: the numeric-array/hex-escape signals were gated behind a small-file-size threshold to cut false positives, which also silently disabled detection on real backdoors whose encoded payload array pushed the file over that size. Those signals are now uncapped by size but weighted low enough that none of them can flag a file alone.
- Added Kingx Development branding and app icon.
- Added "Open File" and "Open File Location" to the right-click menu.

### 1.0.0

- Initial release: recursive `.js` scan, hidden-file detection, quarantine and delete with confirmation, quarantine log.
