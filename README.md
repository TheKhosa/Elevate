# Elevate - UAC Bypass Tool (Node.js)

A Node.js implementation of a UAC (User Access Control) bypass utility for Windows security testing. This tool was converted from PowerShell to Node.js, utilizing Windows API calls through FFI (Foreign Function Interface).

## Important Notice

**This tool is for AUTHORIZED security testing ONLY!**

Use only in:
- Pentesting engagements with proper authorization
- CTF (Capture The Flag) competitions
- Security research in controlled environments
- Educational purposes with proper authorization

**DO NOT use for malicious purposes or on systems you do not own or have explicit permission to test.**

## Overview

This tool implements a UAC bypass technique that:
1. Creates or uses an existing elevated process (default: WUSA.exe)
2. Opens and duplicates the process token
3. Lowers the token's integrity level
4. Creates a restricted token using NtFilterToken
5. Impersonates the security context
6. Spawns a new process with elevated privileges

## Requirements

- **Operating System**: Windows (Win32 only)
- **Node.js**: Version 12.0.0 or higher
- **Dependencies**:
  - koffi (modern FFI library for Windows API calls - no native compilation needed!)

## Installation

1. Clone or download this repository

2. Install dependencies:
```bash
npm install
```

3. Verify installation:
```bash
node index.js --help
```

## Usage

### Basic Syntax

```bash
node index.js <binary_path> [arguments] [--pid <process_id>]
```

### Parameters

- `<binary_path>` (required): Full path to the executable you want to run with elevated privileges
- `[arguments]` (optional): Command-line arguments to pass to the executable
- `--pid <id>` (optional): Use an existing process instead of creating WUSA.exe

### Examples

**Example 1: Spawn elevated cmd.exe**
```bash
node index.js C:\Windows\System32\cmd.exe
```

**Example 2: Run cmd with specific command**
```bash
node index.js C:\Windows\System32\cmd.exe "/c whoami /priv"
```

**Example 3: Use existing process**
```bash
node index.js C:\Windows\System32\cmd.exe --pid 1234
```

**Example 4: Spawn PowerShell elevated**
```bash
node index.js C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
```

## How It Works

### Technical Overview

The tool performs the following steps:

1. **Elevation Check**: Tests if the current session is already elevated
2. **Process Handle Acquisition**: Either creates a new WUSA.exe process or uses an existing process
3. **Token Manipulation**:
   - Opens the process token with maximum allowed permissions
   - Duplicates the token with TOKEN_ALL_ACCESS
4. **Integrity Level Modification**:
   - Allocates and initializes a SID for medium integrity level
   - Sets the token's mandatory integrity label
5. **Token Restriction**:
   - Uses NtFilterToken to create a LUA (Limited User Account) token
   - Duplicates the restricted token for impersonation
6. **Impersonation**: Impersonates the security context using the restricted token
7. **Process Spawning**: Uses CreateProcessWithLogonW to spawn the target process
8. **Cleanup**: Terminates the WUSA process if it was created by the tool

### Windows APIs Used

- **kernel32.dll**:
  - OpenProcess
  - TerminateProcess

- **advapi32.dll**:
  - OpenProcessToken
  - DuplicateTokenEx
  - AllocateAndInitializeSid
  - ImpersonateLoggedOnUser
  - CreateProcessWithLogonW

- **ntdll.dll**:
  - NtSetInformationToken
  - NtFilterToken

- **shell32.dll**:
  - ShellExecuteExW

## Code Structure

```
index.js
├── Type Definitions (Windows types)
├── Structure Definitions (C structs)
├── DLL Bindings (FFI library definitions)
├── Constants (Windows API constants)
├── Utility Functions
├── performUACBypass() - Main bypass logic
└── main() - CLI entry point
```

## Troubleshooting

### Common Issues

**Error: "Failed to create WUSA process"**
- WUSA.exe might be blocked or not available
- Try using an existing elevated process with `--pid`

**Error: "Failed to open process token"**
- The target process might not have the required permissions
- Try a different process ID

**Error: "Session is already elevated"**
- The current session already has elevated privileges
- This tool is designed to elevate from a non-elevated session

**Module not found errors**
- Run `npm install` to ensure all dependencies are installed
- Make sure you're using Node.js 12.0.0 or higher

### Linux/Mac Note

This tool is **Windows-only** because it relies on Windows-specific APIs. It will not work on Linux or macOS. The package.json enforces this with:
```json
"os": ["win32"]
```

### Installation Issues

If you encounter errors during `npm install`:
- This project uses **koffi** which doesn't require native compilation
- If you see errors about `ffi-napi` or `node-gyp`, ensure you have the latest code
- Simply run `npm install` - no build tools required!

## Conversion Notes

This Node.js version was converted from the original PowerShell script. Key differences:

1. **FFI Implementation**: Uses `koffi` (modern FFI library) to call Windows DLLs instead of PowerShell's `Add-Type`
   - No native compilation required (unlike ffi-napi)
   - Better performance and easier to install
   - Works with Node.js 12.0+ including latest versions
2. **Structure Definitions**: Uses `koffi.struct()` to define C structures
3. **Error Handling**: Enhanced error reporting with GetLastError() calls
4. **CLI Interface**: Improved command-line argument parsing
5. **Modularity**: Exported functions can be used programmatically

## Security Considerations

This tool demonstrates:
- Token manipulation techniques
- Process privilege escalation
- UAC bypass methodology

**Defense recommendations:**
- Monitor for suspicious WUSA.exe activity
- Watch for unusual token manipulation
- Implement proper privilege management
- Keep Windows and security software updated

## License

MIT License - See LICENSE file for details

## Disclaimer

The authors of this tool are not responsible for any misuse or damage caused by this program. This tool is provided for educational and authorized security testing purposes only. Use at your own risk and only on systems you own or have explicit written permission to test.

## References

- [Windows Token Manipulation](https://docs.microsoft.com/en-us/windows/win32/secauthz/access-tokens)
- [UAC Architecture](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works)
- [Koffi - Fast and Easy Native Module](https://github.com/Koromix/rygel/tree/master/koffi)

## Contributing

This is a security research tool. If you find bugs or improvements:
1. Ensure changes don't introduce vulnerabilities
2. Test thoroughly on isolated systems
3. Document all changes clearly
4. Follow responsible disclosure practices

---

**Remember: With great power comes great responsibility. Use this tool ethically and legally.**
