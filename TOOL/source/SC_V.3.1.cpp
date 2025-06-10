#include <windows.h>
//System Control (SC) v3.1
#include <stdio.h>
#include <tlhelp32.h>
#include <shlobj.h>
#include <winreg.h>
#include <aclapi.h>
#include <userenv.h>
#include <wincrypt.h>
#include <commctrl.h>
#include <commdlg.h>
#include <time.h>
#include <lm.h>
#include <iphlpapi.h>
#include <psapi.h>
#include <wininet.h>
#include <direct.h>
#include <errno.h>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "netapi32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "comdlg32.lib")

#define ID_BUTTON_EXIT 1001
#define ID_BUTTON_SAFE 1002
#define ID_LIST_OPTIONS 1003
#define ID_BUTTON_EXECUTE 1004
#define ID_BUTTON_HELP 1005
#define ID_STATUS_BAR 1006
#define ID_EDIT_CMD 1007
#define ID_BUTTON_CMD 1008
#define ID_BUTTON_SNAPSHOT 1009
#define ID_BUTTON_THEME 1010

// Global variables for Theme
BOOL g_isDarkMode = FALSE;
HBRUSH g_hBrushDarkBg = NULL;
HBRUSH g_hBrushLightBg = NULL;
COLORREF g_darkTextColor = RGB(240, 240, 240);
COLORREF g_darkBgColor = RGB(45, 45, 48);
COLORREF g_lightTextColor = RGB(0, 0, 0);
COLORREF g_lightBgColor = RGB(255, 255, 255);

// Options list (73 options)
const char* options[] = {
    "1. Disable Task Manager", "2. Enable Task Manager", "3. Delete Task Manager (Dangerous! Permanent!)", "4. Restore Task Manager (Requires Source File)",
    "5. Disable Registry Editor", "6. Enable Registry Editor", "7. Delete Registry Editor (Dangerous! Permanent!)", "8. Restore Registry Editor (Requires Source File)",
    "9. Disable Command Prompt", "10. Enable Command Prompt", "11. Delete Command Prompt (Dangerous! Permanent!)", "12. Restore Command Prompt (Requires Source File)",
    "13. Disable Control Panel", "14. Enable Control Panel", "15. Disable Security Center", "16. Enable Security Center", "17. Disable Automatic Updates", "18. Enable Automatic Updates",
    "19. Disable System Restore", "20. Enable System Restore", "21. Disable Firewall", "22. Enable Firewall", "23. Disable Internet Access", "24. Enable Internet Access",
    "25. Disable USB Devices", "26. Enable USB Devices", "27. Delete System Temporary Files", "28. Clean System Registry", "29. Change Password Policies", "30. Disable User Accounts",
    "31. Enable User Accounts", "32. Change Startup Settings", "33. Disable System Services (Dangerous!)", "34. Enable System Services", "35. Restart System", "36. Shutdown System",
    "37. System Security Scan", "38. Create Restore Point", "39. Restore System from Point", "40. Manage System Processes", "41. Disable Printing", "42. Enable Printing",
    "43. Change System Wallpaper", "44. Reset System Wallpaper", "45. Disable Sleep Feature", "46. Enable Sleep Feature", "47. Change Power Policies", "48. Disable Nightly Updates",
    "49. Enable Nightly Updates", "50. Manage User Accounts", "51. Encrypt Folder (EFS)", "52. Decrypt Folder (EFS)", "53. Block Specific IP", "54. Unblock IP",
    "55. Change DNS to Google", "56. Reset Network Settings", "57. Enable Event Logging", "58. Disable Untrusted Programs", "59. Create Firewall Rule", "60. Run Security Scan",
    "61. Optimize for Performance", "62. Optimize for Energy Saving", "63. Clear DNS Cache", "64. Manage Startup Programs", "65. Generate Health Report", "66. Scan System Files (SFC)",
    "67. Check Disk Errors", "68. Open Performance Monitor", "69. Monitor User Sessions", "70. Open Security Policy", "71. Change Region Settings", "72. Disable Notifications",
    "73. Backup System Settings"
};

const int optionsCount = sizeof(options) / sizeof(options[0]);

// ====================== Verification and Notification Functions ======================
BOOL IsAdmin() {
    BOOL isAdmin = FALSE;
    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
    PSID AdminGroup;
    if (AllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, 
        DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &AdminGroup)) {
        if (!CheckTokenMembership(NULL, AdminGroup, &isAdmin)) {
            isAdmin = FALSE;
        }
        FreeSid(AdminGroup);
    }
    return isAdmin;
}

void ShowWarning(HWND hwnd, const char* message) {
    MessageBox(hwnd, message, "Warning - System Control", MB_ICONWARNING | MB_OK);
}

void ShowError(HWND hwnd, const char* message) {
    MessageBox(hwnd, message, "Error - System Control", MB_ICONERROR | MB_OK);
}

void ShowSuccess(HWND hwnd, const char* message) {
    MessageBox(hwnd, message, "Success - System Control", MB_ICONINFORMATION | MB_OK);
}

BOOL IsSafeMode() {
    HKEY hKey;
    DWORD safeBoot = 0;
    DWORD size = sizeof(DWORD);
    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Option", 
        0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        if (RegQueryValueEx(hKey, "OptionValue", NULL, NULL, (LPBYTE)&safeBoot, &size) == ERROR_SUCCESS) {
            RegCloseKey(hKey);
            return safeBoot != 0;
        }
        RegCloseKey(hKey);
    }
    return FALSE;
}

// ====================== System Snapshot Function ======================
void CreateSystemSnapshot(HWND hwnd) {
    SYSTEMTIME st;
    GetLocalTime(&st);
    char dirName[128];
    sprintf(dirName, "SC_Snapshot_%04d-%02d-%02d_%02d-%02d-%02d", 
            st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);

    if (_mkdir(dirName)) {
        if (errno != EEXIST) {
            ShowError(hwnd, "Failed to create snapshot directory!");
            return;
        }
    }

    char command[512];
    char message[512];

    ShowSuccess(hwnd, "Creating snapshot... This may take a moment.");
    // 1. Export Registry HKLM
    sprintf(command, "reg export HKLM \"%s\\registry_HKLM.reg\" /y", dirName);
    system(command);
    // 2. Export Registry HKCU
    sprintf(command, "reg export HKCU \"%s\\registry_HKCU.reg\" /y", dirName);
    system(command);
    // 3. List Services
    sprintf(command, "sc query state=all > \"%s\\services.txt\"", dirName);
    system(command);
    // 4. List Processes
    sprintf(command, "tasklist > \"%s\\processes.txt\"", dirName);
    system(command);
    // 5. Network Info
    sprintf(command, "ipconfig /all > \"%s\\network_info.txt\"", dirName);
    system(command);

    sprintf(message, "System snapshot created successfully in the folder:\n%s", dirName);
    ShowSuccess(hwnd, message);
}

// ====================== File Existence Check ======================
BOOL FileExists(LPCSTR path) {
    DWORD attrib = GetFileAttributesA(path);
    return (attrib != INVALID_FILE_ATTRIBUTES && 
           !(attrib & FILE_ATTRIBUTE_DIRECTORY));
}

// ====================== NEW: Restore Functions with File Selection ======================
void RestoreSystemFile(HWND hwnd, const char* targetPath, const char* toolName) {
    OPENFILENAMEA ofn;
    char sourcePath[MAX_PATH] = {0};

    ZeroMemory(&ofn, sizeof(ofn));
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = hwnd;
    ofn.lpstrFilter = "Executable Files (*.exe)\0*.exe\0All Files (*.*)\0*.*\0";
    ofn.lpstrFile = sourcePath;
    ofn.nMaxFile = MAX_PATH;
    ofn.lpstrTitle = "Select the source file for restoration";
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_EXPLORER;
    
    if (!GetOpenFileNameA(&ofn)) {
        ShowError(hwnd, "Operation canceled or invalid file selected");
        return;
    }
    
    // Check if target file already exists
    if (FileExists(targetPath)) {
        char msg[256];
        sprintf(msg, "%s already exists at:\n%s\n\nRestoration aborted to prevent overwriting.", toolName, targetPath);
        ShowError(hwnd, msg);
        return;
    }
    
    // Attempt to copy the file
    if (CopyFileA(sourcePath, targetPath, FALSE)) {
        char msg[256];
        sprintf(msg, "%s restored successfully!\n\nSource: %s\nTarget: %s", toolName, sourcePath, targetPath);
        ShowSuccess(hwnd, msg);
    } else {
        DWORD error = GetLastError();
        char msg[256];
        if (error == ERROR_ACCESS_DENIED) {
            sprintf(msg, "Access denied! Failed to restore %s.\n\nPlease ensure you have administrator privileges.", toolName);
        } else {
            sprintf(msg, "Failed to restore %s (Error code: %d)", toolName, error);
        }
        ShowError(hwnd, msg);
    }
}

// ====================== ALL System Management Functions ======================

// Options 1-4
void DisableTaskManager() { 
    HKEY hKey; 
    DWORD v = 1; 
    if(RegCreateKeyEx(HKEY_CURRENT_USER, 
        "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", 
        0, NULL, 0, KEY_WRITE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
        RegSetValueEx(hKey, "DisableTaskMgr", 0, REG_DWORD, (BYTE*)&v, sizeof(v));
        RegCloseKey(hKey);
    }
}

void EnableTaskManager() { 
    HKEY hKey; 
    if(RegOpenKeyEx(HKEY_CURRENT_USER, 
        "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", 
        0, KEY_WRITE, &hKey) == ERROR_SUCCESS) {
        RegDeleteValue(hKey, "DisableTaskMgr");
        RegCloseKey(hKey);
    }
}

void DeleteTaskManager() { 
    DeleteFile("C:\\Windows\\System32\\Taskmgr.exe"); 
}

void RestoreTaskManager(HWND hwnd) {
    RestoreSystemFile(hwnd, "C:\\Windows\\System32\\taskmgr.exe", "Task Manager");
}

// Options 5-8
void DisableRegistryEditor() { 
    HKEY hKey; 
    DWORD v = 1; 
    if(RegCreateKeyEx(HKEY_CURRENT_USER,
        "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
        0, NULL, 0, KEY_WRITE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
        RegSetValueEx(hKey, "DisableRegistryTools", 0, REG_DWORD, (BYTE*)&v, sizeof(v));
        RegCloseKey(hKey);
    }
}

void EnableRegistryEditor() { 
    HKEY hKey; 
    if(RegOpenKeyEx(HKEY_CURRENT_USER, 
        "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", 
        0, KEY_WRITE, &hKey) == ERROR_SUCCESS) {
        RegDeleteValue(hKey, "DisableRegistryTools");
        RegCloseKey(hKey);
    }
}

void DeleteRegistryEditor() { 
    DeleteFile("C:\\Windows\\regedit.exe"); 
}

void RestoreRegistryEditor(HWND hwnd) {
    RestoreSystemFile(hwnd, "C:\\Windows\\regedit.exe", "Registry Editor");
}

// Options 9-12
void DisableCMD() { 
    HKEY hKey; 
    DWORD v = 1; 
    if(RegCreateKeyEx(HKEY_CURRENT_USER,
        "Software\\Policies\\Microsoft\\Windows\\System",
        0, NULL, 0, KEY_WRITE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
        RegSetValueEx(hKey, "DisableCMD", 0, REG_DWORD, (BYTE*)&v, sizeof(v));
        RegCloseKey(hKey);
    }
}

void EnableCMD() { 
    HKEY hKey; 
    if(RegOpenKeyEx(HKEY_CURRENT_USER,
        "Software\\Policies\\Microsoft\\Windows\\System",
        0, KEY_WRITE, &hKey) == ERROR_SUCCESS) {
        RegDeleteValue(hKey, "DisableCMD");
        RegCloseKey(hKey);
    }
}

void DeleteCMD() { 
    DeleteFile("C:\\Windows\\System32\\cmd.exe"); 
}

void RestoreCommandPrompt(HWND hwnd) {
    RestoreSystemFile(hwnd, "C:\\Windows\\System32\\cmd.exe", "Command Prompt");
}

// Options 13-14
void DisableControlPanel() { 
    HKEY hKey; 
    DWORD v = 1; 
    if(RegCreateKeyEx(HKEY_CURRENT_USER,
        "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer",
        0, NULL, 0, KEY_WRITE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
        RegSetValueEx(hKey, "NoControlPanel", 0, REG_DWORD, (BYTE*)&v, sizeof(v));
        RegCloseKey(hKey);
    }
}

void EnableControlPanel() { 
    HKEY hKey; 
    if(RegOpenKeyEx(HKEY_CURRENT_USER,
        "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer",
        0, KEY_WRITE, &hKey) == ERROR_SUCCESS) {
        RegDeleteValue(hKey, "NoControlPanel");
        RegCloseKey(hKey);
    }
}

// Options 15-16
void DisableSecurityCenter() { 
    HKEY hKey; 
    DWORD v = 1; 
    if(RegCreateKeyEx(HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Policies\\Microsoft\\Windows Defender",
        0, NULL, 0, KEY_WRITE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
        RegSetValueEx(hKey, "DisableAntiSpyware", 0, REG_DWORD, (BYTE*)&v, sizeof(v));
        RegCloseKey(hKey);
    }
}

void EnableSecurityCenter() { 
    HKEY hKey; 
    if(RegOpenKeyEx(HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Policies\\Microsoft\\Windows Defender",
        0, KEY_WRITE, &hKey) == ERROR_SUCCESS) {
        RegDeleteValue(hKey, "DisableAntiSpyware");
        RegCloseKey(hKey);
    }
}

// Options 17-18
void DisableWindowsUpdate() { 
    HKEY hKey; 
    DWORD v = 1; 
    if(RegCreateKeyEx(HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU",
        0, NULL, 0, KEY_WRITE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
        RegSetValueEx(hKey, "NoAutoUpdate", 0, REG_DWORD, (BYTE*)&v, sizeof(v));
        RegCloseKey(hKey);
    }
}

void EnableWindowsUpdate() { 
    HKEY hKey; 
    if(RegOpenKeyEx(HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU",
        0, KEY_WRITE, &hKey) == ERROR_SUCCESS) {
        RegDeleteValue(hKey, "NoAutoUpdate");
        RegCloseKey(hKey);
    }
}

// Options 19-20
void DisableSystemRestore() { 
    HKEY hKey; 
    DWORD v = 1; 
    if(RegCreateKeyEx(HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Policies\\Microsoft\\Windows NT\\SystemRestore",
        0, NULL, 0, KEY_WRITE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
        RegSetValueEx(hKey, "DisableSR", 0, REG_DWORD, (BYTE*)&v, sizeof(v));
        RegCloseKey(hKey);
    }
}

void EnableSystemRestore() { 
    HKEY hKey; 
    if(RegOpenKeyEx(HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Policies\\Microsoft\\Windows NT\\SystemRestore",
        0, KEY_WRITE, &hKey) == ERROR_SUCCESS) {
        RegDeleteValue(hKey, "DisableSR");
        RegCloseKey(hKey);
    }
}

// Options 21-24
void DisableFirewall() { system("netsh advfirewall set allprofiles state off"); }
void EnableFirewall() { system("netsh advfirewall set allprofiles state on"); }
void DisableInternet() { system("ipconfig /release"); }
void EnableInternet() { system("ipconfig /renew"); }

// Options 25-26
void DisableUSB() { 
    HKEY hKey; 
    DWORD v = 4; 
    if(RegCreateKeyEx(HKEY_LOCAL_MACHINE,
        "SYSTEM\\CurrentControlSet\\Services\\USBSTOR",
        0, NULL, 0, KEY_WRITE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
        RegSetValueEx(hKey, "Start", 0, REG_DWORD, (BYTE*)&v, sizeof(v));
        RegCloseKey(hKey);
    }
}

void EnableUSB() { 
    HKEY hKey; 
    DWORD v = 3; 
    if(RegCreateKeyEx(HKEY_LOCAL_MACHINE,
        "SYSTEM\\CurrentControlSet\\Services\\USBSTOR",
        0, NULL, 0, KEY_WRITE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
        RegSetValueEx(hKey, "Start", 0, REG_DWORD, (BYTE*)&v, sizeof(v));
        RegCloseKey(hKey);
    }
}

// Options 27-29
void CleanTempFiles() { 
    system("del /f /s /q %temp%\\*.*"); 
    system("del /f /s /q C:\\Windows\\Temp\\*.*"); 
}

void CleanRegistry() { 
    system("reg delete HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU /f"); 
    system("reg delete HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\OpenSaveMRU /f"); 
}

void ChangePasswordPolicy() { 
    HKEY hKey; 
    DWORD v = 1; 
    if(RegCreateKeyEx(HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
        0, NULL, 0, KEY_WRITE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
        RegSetValueEx(hKey, "DisableDomainCreds", 0, REG_DWORD, (BYTE*)&v, sizeof(v)); 
        RegSetValueEx(hKey, "DontDisplayLastUserName", 0, REG_DWORD, (BYTE*)&v, sizeof(v)); 
        RegSetValueEx(hKey, "PasswordExpiryWarning", 0, REG_DWORD, (BYTE*)&v, sizeof(v)); 
        RegCloseKey(hKey);
    }
}

// Options 30-31
void DisableUserAccounts() { 
    system("net user Guest /active:no"); 
    system("net user Administrator /active:no"); 
}

void EnableUserAccounts() { 
    system("net user Guest /active:yes"); 
    system("net user Administrator /active:yes"); 
}

// Option 32
void ChangeStartupSettings() { 
    HKEY hKey; 
    DWORD v = 1; 
    if(RegCreateKeyEx(HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer",
        0, NULL, 0, KEY_WRITE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
        RegSetValueEx(hKey, "NoStartMenuMorePrograms", 0, REG_DWORD, (BYTE*)&v, sizeof(v));
        RegSetValueEx(hKey, "NoStartMenuMFUprogramsList", 0, REG_DWORD, (BYTE*)&v, sizeof(v));
        RegCloseKey(hKey);
    }
}

// Options 33-34
void DisableSystemServices() { 
    system("sc config WinDefend start= disabled"); 
    system("sc config wuauserv start= disabled"); 
}

void EnableSystemServices() { 
    system("sc config WinDefend start= auto"); 
    system("sc config wuauserv start= auto"); 
}

// Options 35-36
void RestartSystem() { system("shutdown /r /t 0"); }
void ShutdownSystem() { system("shutdown /s /t 0"); }

// Options 37-40
void SystemSecurityScan() { system("start msert /q"); }
void CreateRestorePoint() { system("powershell -Command \"Checkpoint-Computer -Description 'SC_Restore_Point'\""); }
void RestoreSystemFromPoint() { ShellExecute(NULL, "open", "rstrui.exe", NULL, NULL, SW_SHOW); }
void ManageSystemProcesses() { ShellExecute(NULL, "open", "taskmgr.exe", NULL, NULL, SW_SHOW); }

// Options 41-42
void DisablePrinting() { 
    system("net stop spooler"); 
    system("sc config spooler start= disabled"); 
}

void EnablePrinting() { 
    system("sc config spooler start= auto"); 
    system("net start spooler"); 
}

// Options 43-44
void ChangeWallpaper() { 
    SystemParametersInfo(SPI_SETDESKWALLPAPER, 0, 
        (PVOID)"C:\\Windows\\Web\\Wallpaper\\Windows\\img0.jpg", 
        SPIF_UPDATEINIFILE | SPIF_SENDCHANGE); 
}

void ResetWallpaper() { 
    SystemParametersInfo(SPI_SETDESKWALLPAPER, 0, (PVOID)"", 
        SPIF_UPDATEINIFILE | SPIF_SENDCHANGE); 
}

// Options 45-46
void DisableSleep() { system("powercfg /h off"); }
void EnableSleep() { system("powercfg /h on"); }

// Option 47
void ChangePowerPolicies() { ShellExecute(NULL, "open", "powercfg.cpl", NULL, NULL, SW_SHOW); }

// Options 48-49
void DisableNightlyUpdates() { DisableWindowsUpdate(); }
void EnableNightlyUpdates() { EnableWindowsUpdate(); }

// Option 50
void ManageUserAccounts() { system("control userpasswords2"); }

// Options 51-52
void EncryptFolder() { 
    system("mkdir C:\\SecureFolder 2>nul"); 
    system("cipher /e /s:C:\\SecureFolder"); 
}

void DecryptFolder() { system("cipher /d /s:C:\\SecureFolder"); }

// Options 53-54
void BlockIP() { 
    system("netsh advfirewall firewall add rule name=\"SC_BlockedIP\" dir=in action=block remoteip=192.168.1.100"); 
}

void UnblockIP() { 
    system("netsh advfirewall firewall delete rule name=\"SC_BlockedIP\""); 
}

// Options 55-56
void ChangeDNSToGoogle() { 
    system("netsh interface ip set dns name=\"Ethernet\" source=static address=8.8.8.8 validate=no"); 
    system("netsh interface ip add dns name=\"Ethernet\" address=8.8.4.4 index=2 validate=no"); 
    system("netsh interface ip set dns name=\"Wi-Fi\" source=static address=8.8.8.8 validate=no"); 
    system("netsh interface ip add dns name=\"Wi-Fi\" address=8.8.4.4 index=2 validate=no"); 
}

void ResetNetworkSettings() { 
    system("netsh int ip reset"); 
    system("netsh winsock reset"); 
}

// Options 57-58
void EnableEventLogging() { 
    system("wevtutil set-log Application /enabled:true"); 
    system("wevtutil set-log Security /enabled:true"); 
    system("wevtutil set-log System /enabled:true"); 
}

void DisableUntrustedPrograms() { 
    HKEY hKey; 
    DWORD v = 1; 
    if(RegCreateKeyEx(HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Policies\\Microsoft\\Windows\\Safer\\CodeIdentifiers",
        0, NULL, 0, KEY_WRITE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
        RegSetValueEx(hKey, "AuthenticodeEnabled", 0, REG_DWORD, (BYTE*)&v, sizeof(v));
        RegCloseKey(hKey);
    }
}

// Options 59-60
void CreateFirewallRule() { 
    system("netsh advfirewall firewall add rule name=\"SC_BlockPorts\" protocol=TCP dir=in localport=80-90 action=block"); 
}

void RunSecurityScan() { system("start msert /q"); }

// Options 61-62
void OptimizeForPerformance() { 
    system("powercfg /s 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c"); 
}

void OptimizeForEnergy() { 
    system("powercfg /s a1841308-3541-4fab-bc81-f71556f20b4a"); 
}

// Option 63-64
void ClearDNSCache() { system("ipconfig /flushdns"); }
void ManageStartupPrograms() { ShellExecute(NULL, "open", "msconfig", NULL, NULL, SW_SHOW); }

// Option 65-67
void GenerateHealthReport() { system("perfmon /report"); }
void RunSFCScan() { system("sfc /scannow"); }
void CheckDiskErrors() { system("chkdsk /scan"); }

// Option 68-70
void OpenPerformanceMonitor() { ShellExecute(NULL, "open", "perfmon", NULL, NULL, SW_SHOW); }
void MonitorUserSessions() { system("start cmd /k query session"); }
void OpenSecurityPolicy() { ShellExecute(NULL, "open", "secpol.msc", NULL, NULL, SW_SHOW); }

// Option 71
void ChangeRegionSettings() { ShellExecute(NULL, "open", "intl.cpl", NULL, NULL, SW_SHOW); }

// Option 72
void DisableNotifications() { 
    HKEY hKey; 
    DWORD v = 1; 
    if(RegCreateKeyEx(HKEY_CURRENT_USER,
        "Software\\Policies\\Microsoft\\Windows\\Explorer",
        0, NULL, 0, KEY_WRITE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
        RegSetValueEx(hKey, "DisableNotificationCenter", 0, REG_DWORD, (BYTE*)&v, sizeof(v));
        RegCloseKey(hKey);
    }
}

// Option 73
void BackupSystemSettings() { 
    SYSTEMTIME st; 
    GetLocalTime(&st); 
    char filename[128]; 
    sprintf(filename, "system_backup_%04d%02d%02d.reg", st.wYear, st.wMonth, st.wDay); 
    char cmd[256]; 
    sprintf(cmd, "reg export HKLM\\SOFTWARE %s", filename); 
    system(cmd); 
}

// ====================== Helper function for dangerous operations ======================
BOOL IsDangerousOperation(int option) {
    switch(option) {
        case 2:  // Delete Task Manager
        case 6:  // Delete Registry Editor
        case 10: // Delete CMD
        case 32: // Disable System Services
            return TRUE;
        default:
            return FALSE;
    }
}

// ====================== Command Execution Functions ======================
void ExecuteCommand(int option, HWND hwnd) {
    switch(option) {
        case 0: DisableTaskManager(); ShowSuccess(hwnd, "Task Manager disabled successfully"); break;
        case 1: EnableTaskManager(); ShowSuccess(hwnd, "Task Manager enabled successfully"); break;
        case 2: if(MessageBox(hwnd, "WARNING: This will PERMANENTLY delete Task Manager!\nThis action cannot be undone!\nAre you absolutely sure?", "CRITICAL WARNING", MB_ICONERROR | MB_YESNO) == IDYES) { DeleteTaskManager(); ShowSuccess(hwnd, "Task Manager PERMANENTLY deleted!"); } break;
        case 3: RestoreTaskManager(hwnd); break;
        case 4: DisableRegistryEditor(); ShowSuccess(hwnd, "Registry Editor disabled successfully"); break;
        case 5: EnableRegistryEditor(); ShowSuccess(hwnd, "Registry Editor enabled successfully"); break;
        case 6: if(MessageBox(hwnd, "WARNING: This will PERMANENTLY delete Registry Editor!\nYour system may become UNUSABLE!\nAre you absolutely sure?", "CRITICAL WARNING", MB_ICONERROR | MB_YESNO) == IDYES) { DeleteRegistryEditor(); ShowSuccess(hwnd, "Registry Editor PERMANENTLY deleted!"); } break;
        case 7: RestoreRegistryEditor(hwnd); break;
        case 8: DisableCMD(); ShowSuccess(hwnd, "Command Prompt disabled successfully"); break;
        case 9: EnableCMD(); ShowSuccess(hwnd, "Command Prompt enabled successfully"); break;
        case 10: if(MessageBox(hwnd, "WARNING: This will PERMANENTLY delete Command Prompt!\nThis action cannot be undone!\nAre you absolutely sure?", "CRITICAL WARNING", MB_ICONERROR | MB_YESNO) == IDYES) { DeleteCMD(); ShowSuccess(hwnd, "Command Prompt PERMANENTLY deleted!"); } break;
        case 11: RestoreCommandPrompt(hwnd); break;
        case 12: DisableControlPanel(); ShowSuccess(hwnd, "Control Panel disabled successfully"); break;
        case 13: EnableControlPanel(); ShowSuccess(hwnd, "Control Panel enabled successfully"); break;
        case 14: DisableSecurityCenter(); ShowSuccess(hwnd, "Security Center disabled successfully"); break;
        case 15: EnableSecurityCenter(); ShowSuccess(hwnd, "Security Center enabled successfully"); break;
        case 16: DisableWindowsUpdate(); ShowSuccess(hwnd, "Automatic Updates disabled successfully"); break;
        case 17: EnableWindowsUpdate(); ShowSuccess(hwnd, "Automatic Updates enabled successfully"); break;
        case 18: DisableSystemRestore(); ShowSuccess(hwnd, "System Restore disabled successfully"); break;
        case 19: EnableSystemRestore(); ShowSuccess(hwnd, "System Restore enabled successfully"); break;
        case 20: DisableFirewall(); ShowSuccess(hwnd, "Firewall disabled successfully"); break;
        case 21: EnableFirewall(); ShowSuccess(hwnd, "Firewall enabled successfully"); break;
        case 22: DisableInternet(); ShowSuccess(hwnd, "Internet access disabled successfully"); break;
        case 23: EnableInternet(); ShowSuccess(hwnd, "Internet access enabled successfully"); break;
        case 24: DisableUSB(); ShowSuccess(hwnd, "USB devices disabled successfully"); break;
        case 25: EnableUSB(); ShowSuccess(hwnd, "USB devices enabled successfully"); break;
        case 26: CleanTempFiles(); ShowSuccess(hwnd, "System temporary files deleted successfully"); break;
        case 27: CleanRegistry(); ShowSuccess(hwnd, "System registry cleaned successfully"); break;
        case 28: ChangePasswordPolicy(); ShowSuccess(hwnd, "Password policies changed successfully"); break;
        case 29: DisableUserAccounts(); ShowSuccess(hwnd, "User accounts disabled successfully"); break;
        case 30: EnableUserAccounts(); ShowSuccess(hwnd, "User accounts enabled successfully"); break;
        case 31: ChangeStartupSettings(); ShowSuccess(hwnd, "Startup settings changed successfully"); break;
        case 32: if(MessageBox(hwnd, "This action is dangerous and may destabilize the system!\nContinue?", "Severe Warning", MB_ICONWARNING | MB_YESNO) == IDYES) { DisableSystemServices(); ShowSuccess(hwnd, "System services disabled successfully"); } break;
        case 33: EnableSystemServices(); ShowSuccess(hwnd, "System services enabled successfully"); break;
        case 34: RestartSystem(); break;
        case 35: ShutdownSystem(); break;
        case 36: SystemSecurityScan(); ShowSuccess(hwnd, "System security scan started."); break;
        case 37: CreateRestorePoint(); ShowSuccess(hwnd, "Restore point creation initiated."); break;
        case 38: RestoreSystemFromPoint(); ShowSuccess(hwnd, "System Restore window opened."); break;
        case 39: ManageSystemProcesses(); ShowSuccess(hwnd, "Task Manager opened."); break;
        case 40: DisablePrinting(); ShowSuccess(hwnd, "Printing disabled successfully"); break;
        case 41: EnablePrinting(); ShowSuccess(hwnd, "Printing enabled successfully"); break;
        case 42: ChangeWallpaper(); ShowSuccess(hwnd, "System wallpaper changed successfully"); break;
        case 43: ResetWallpaper(); ShowSuccess(hwnd, "System wallpaper reset successfully"); break;
        case 44: DisableSleep(); ShowSuccess(hwnd, "Sleep feature disabled successfully"); break;
        case 45: EnableSleep(); ShowSuccess(hwnd, "Sleep feature enabled successfully"); break;
        case 46: ChangePowerPolicies(); ShowSuccess(hwnd, "Power options opened."); break;
        case 47: DisableNightlyUpdates(); ShowSuccess(hwnd, "Automatic Updates disabled successfully"); break;
        case 48: EnableNightlyUpdates(); ShowSuccess(hwnd, "Automatic Updates enabled successfully"); break;
        case 49: ManageUserAccounts(); ShowSuccess(hwnd, "User accounts manager opened"); break;
        case 50: EncryptFolder(); ShowSuccess(hwnd, "Folder C:\\SecureFolder encrypted successfully"); break;
        case 51: DecryptFolder(); ShowSuccess(hwnd, "Folder C:\\SecureFolder decrypted successfully"); break;
        case 52: BlockIP(); ShowSuccess(hwnd, "IP blocked successfully (Note: IP is hardcoded)"); break;
        case 53: UnblockIP(); ShowSuccess(hwnd, "IP unblocked successfully"); break;
        case 54: ChangeDNSToGoogle(); ShowSuccess(hwnd, "DNS changed to Google Public DNS"); break;
        case 55: ResetNetworkSettings(); ShowSuccess(hwnd, "Network settings reset. A restart may be required."); break;
        case 56: EnableEventLogging(); ShowSuccess(hwnd, "Event logging enabled"); break;
        case 57: DisableUntrustedPrograms(); ShowSuccess(hwnd, "Untrusted programs disabled"); break;
        case 58: CreateFirewallRule(); ShowSuccess(hwnd, "Firewall rule created to block TCP ports 80-90."); break;
        case 59: RunSecurityScan(); ShowSuccess(hwnd, "Security scan started"); break;
        case 60: OptimizeForPerformance(); ShowSuccess(hwnd, "System optimized for performance"); break;
        case 61: OptimizeForEnergy(); ShowSuccess(hwnd, "System optimized for energy saving"); break;
        case 62: ClearDNSCache(); ShowSuccess(hwnd, "DNS cache cleared"); break;
        case 63: ManageStartupPrograms(); ShowSuccess(hwnd, "System Configuration (msconfig) opened"); break;
        case 64: GenerateHealthReport(); ShowSuccess(hwnd, "System health report generation started"); break;
        case 65: RunSFCScan(); ShowSuccess(hwnd, "System File Checker started. This may take time."); break;
        case 66: CheckDiskErrors(); ShowSuccess(hwnd, "Disk error check initiated"); break;
        case 67: OpenPerformanceMonitor(); ShowSuccess(hwnd, "Performance monitor opened"); break;
        case 68: MonitorUserSessions(); ShowSuccess(hwnd, "User sessions monitor opened"); break;
        case 69: OpenSecurityPolicy(); ShowSuccess(hwnd, "Security policy manager opened"); break;
        case 70: ChangeRegionSettings(); ShowSuccess(hwnd, "Region settings opened"); break;
        case 71: DisableNotifications(); ShowSuccess(hwnd, "System notifications disabled"); break;
        case 72: BackupSystemSettings(); ShowSuccess(hwnd, "System settings backup created in the program's folder."); break;
        default: ShowError(hwnd, "Unknown option"); break;
    }
}

// ====================== Graphical User Interface ======================
LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch(msg) {
        case WM_CREATE: {
            g_hBrushDarkBg = CreateSolidBrush(g_darkBgColor);
            g_hBrushLightBg = (HBRUSH)(COLOR_WINDOW + 1);
            CreateWindow("BUTTON", "Exit", WS_VISIBLE | WS_CHILD, 10, 560, 80, 30, hwnd, (HMENU)ID_BUTTON_EXIT, NULL, NULL);
            CreateWindow("BUTTON", "Safe Mode", WS_VISIBLE | WS_CHILD, 100, 560, 90, 30, hwnd, (HMENU)ID_BUTTON_SAFE, NULL, NULL);
            CreateWindow("BUTTON", "Help", WS_VISIBLE | WS_CHILD, 200, 560, 80, 30, hwnd, (HMENU)ID_BUTTON_HELP, NULL, NULL);
            CreateWindow("BUTTON", "Toggle Theme", WS_VISIBLE | WS_CHILD, 290, 560, 110, 30, hwnd, (HMENU)ID_BUTTON_THEME, NULL, NULL);
            CreateWindow("BUTTON", "Take Snapshot", WS_VISIBLE | WS_CHILD, 410, 560, 120, 30, hwnd, (HMENU)ID_BUTTON_SNAPSHOT, NULL, NULL);
            CreateWindow("BUTTON", "Execute Selected Action", WS_VISIBLE | WS_CHILD | BS_CENTER, 20, 515, 510, 35, hwnd, (HMENU)ID_BUTTON_EXECUTE, NULL, NULL);
            HWND list = CreateWindow("LISTBOX", "", WS_VISIBLE | WS_CHILD | WS_BORDER | WS_VSCROLL | LBS_NOTIFY, 20, 20, 510, 420, hwnd, (HMENU)ID_LIST_OPTIONS, NULL, NULL);
            for (int i = 0; i < optionsCount; i++) { SendMessage(list, LB_ADDSTRING, 0, (LPARAM)options[i]); }
            HWND statusBar = CreateWindow(STATUSCLASSNAME, "", WS_VISIBLE | WS_CHILD | SBARS_SIZEGRIP, 0, 0, 0, 0, hwnd, (HMENU)ID_STATUS_BAR, NULL, NULL);
            char status[256];
            sprintf(status, "System Control v3.1 | Admin Mode: %s | Safe Mode: %s", IsAdmin() ? "Yes" : "No", IsSafeMode() ? "Yes" : "No");
            SendMessage(statusBar, SB_SETTEXT, 0, (LPARAM)status);
            CreateWindow("EDIT", "", WS_VISIBLE | WS_CHILD | WS_BORDER | ES_AUTOHSCROLL, 20, 450, 430, 25, hwnd, (HMENU)ID_EDIT_CMD, NULL, NULL);
            CreateWindow("BUTTON", "Run", WS_VISIBLE | WS_CHILD, 460, 450, 70, 25, hwnd, (HMENU)ID_BUTTON_CMD, NULL, NULL);
            break;
        }
        case WM_CTLCOLORSTATIC:
        case WM_CTLCOLORBTN: {
            if (g_isDarkMode) {
                HDC hdc = (HDC)wParam;
                SetTextColor(hdc, g_darkTextColor);
                SetBkColor(hdc, g_darkBgColor);
                return (LRESULT)g_hBrushDarkBg;
            }
            return DefWindowProc(hwnd, msg, wParam, lParam);
        }
        case WM_CTLCOLOREDIT:
        case WM_CTLCOLORLISTBOX: {
            if (g_isDarkMode) {
                HDC hdc = (HDC)wParam;
                SetTextColor(hdc, g_darkTextColor);
                SetBkColor(hdc, RGB(60, 60, 60));
                static HBRUSH hBrushDarkEdit;
                if (!hBrushDarkEdit) hBrushDarkEdit = CreateSolidBrush(RGB(60, 60, 60));
                return (LRESULT)hBrushDarkEdit;
            }
            return DefWindowProc(hwnd, msg, wParam, lParam);
        }
        case WM_COMMAND: {
            switch(LOWORD(wParam)) {
                case ID_BUTTON_EXIT: PostQuitMessage(0); break;
                case ID_BUTTON_SAFE: MessageBox(hwnd, "To start system in Safe Mode:\n\n1. Restart your computer\n2. During boot, hold F8 key\n3. Select 'Safe Mode' from menu\n\nRecommended for dangerous operations", "Safe Mode", MB_ICONINFORMATION | MB_OK); break;
                case ID_BUTTON_EXECUTE: {
                    HWND list = GetDlgItem(hwnd, ID_LIST_OPTIONS);
                    int selected = SendMessage(list, LB_GETCURSEL, 0, 0);
                    if (selected != LB_ERR) {
                        if (IsDangerousOperation(selected)) {
                            if (MessageBox(hwnd, "This is a potentially dangerous operation.\nWould you like to create a system snapshot before proceeding?", "Precaution", MB_ICONQUESTION | MB_YESNO) == IDYES) {
                                CreateSystemSnapshot(hwnd);
                            }
                        }
                        ExecuteCommand(selected, hwnd);
                    } else { ShowError(hwnd, "Please select an option from the list"); }
                    break;
                }
                case ID_BUTTON_HELP: MessageBox(hwnd, "System Control (SC) - Version 3.1\n\nAdvanced Windows control tool\nRequires admin privileges for full operation\n\nNew in v3.1:\n- File restoration feature for critical system tools\n- Enhanced safety checks before file operations\n\nDeveloper: SC Team", "Help", MB_ICONINFORMATION | MB_OK); break;
                case ID_BUTTON_CMD: {
                    char cmd[1024];
                    GetWindowText(GetDlgItem(hwnd, ID_EDIT_CMD), cmd, sizeof(cmd));
                    if (strlen(cmd) > 0) { system(cmd); ShowSuccess(hwnd, "Command executed successfully"); }
                    break;
                }
                case ID_BUTTON_SNAPSHOT: CreateSystemSnapshot(hwnd); break;
                case ID_BUTTON_THEME:
                    g_isDarkMode = !g_isDarkMode;
                    InvalidateRect(hwnd, NULL, TRUE);
                    UpdateWindow(hwnd);
                    break;
            }
            break;
        }
        case WM_ERASEBKGND: {
            HDC hdc = (HDC)wParam; 
            RECT rect; 
            GetClientRect(hwnd, &rect);
            FillRect(hdc, &rect, g_isDarkMode ? g_hBrushDarkBg : g_hBrushLightBg);
            return 1;
        }
        case WM_SIZE: { 
            SendMessage(GetDlgItem(hwnd, ID_STATUS_BAR), WM_SIZE, 0, 0); 
            break; 
        }
        case WM_CLOSE: DestroyWindow(hwnd); break;
        case WM_DESTROY: 
            DeleteObject(g_hBrushDarkBg); 
            PostQuitMessage(0); 
            break;
        default: return DefWindowProc(hwnd, msg, wParam, lParam);
    }
    return 0;
}

// ====================== WinMain Entry Point ======================
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    if (!IsAdmin()) { 
        MessageBox(NULL, "This tool requires administrator privileges!\nPlease run as administrator.", "Permission Error", MB_ICONERROR | MB_OK); 
        return 1; 
    }
    if (MessageBox(NULL, "WARNING: This is a powerful tool and may disable your system!\n\nUse with caution. Creating snapshots before dangerous operations is highly recommended.\n\nContinue?", "Security Warning", MB_ICONWARNING | MB_YESNO) == IDNO) { 
        return 0; 
    }

    WNDCLASSEX wc = {0};
    wc.cbSize = sizeof(WNDCLASSEX); 
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = WndProc; 
    wc.hInstance = hInstance; 
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1); 
    wc.lpszClassName = "SCWindowClass";
    
    if (!RegisterClassEx(&wc)) { 
        MessageBox(NULL, "Window class registration failed!", "Error", MB_ICONERROR | MB_OK); 
        return 1; 
    }

    HWND hwnd = CreateWindowEx(0, "SCWindowClass", "System Control (SC) v3.1 - Advanced Control Panel", 
        WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, 560, 650, NULL, NULL, hInstance, NULL);
    
    if (!hwnd) { 
        MessageBox(NULL, "Window creation failed!", "Error", MB_ICONERROR | MB_OK); 
        return 1; 
    }

    ShowWindow(hwnd, nCmdShow); 
    UpdateWindow(hwnd); 
    
    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0) > 0) { 
        TranslateMessage(&msg); 
        DispatchMessage(&msg); 
    }
    return (int)msg.wParam;
}
