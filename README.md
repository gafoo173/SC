System Control (SC) v3.1 - Advanced Control Panel ⚙️
System Control (SC) v3.1 is a powerful and advanced tool for system management and customization on the Windows operating system. Developed in C++, this tool utilizes the Windows API to provide a wide range of functionalities for controlling various aspects of the system, from managing core components like Task Manager and Registry Editor to advanced maintenance and security tasks.

⚠️ WARNING: This tool is extremely powerful and may disable your system if not used carefully. It is highly recommended to create system snapshots before performing any dangerous operations.

Key Features ✨
System Control (SC) v3.1 offers a broad spectrum of features, categorized into main sections:

I. Core System Tool Management (Options 1-12) 🛠️
These features allow you to disable, enable, or even permanently delete (dangerously!) essential Windows tools.

Task Manager: Disable/Enable/Delete/Restore Task Manager.

Registry Editor: Disable/Enable/Delete/Restore Registry Editor.

Command Prompt (CMD): Disable/Enable/Delete/Restore Command Prompt.

II. System & Security Settings (Options 13-26) 🔒
Provides precise control over vital security and system features.

Control Panel: Disable/Enable access to the Control Panel.

Security Center: Disable/Enable Windows Defender Security Center.

Automatic Updates: Disable/Enable automatic Windows updates.

System Restore: Disable/Enable the System Restore feature.

Firewall: Disable/Enable Windows Firewall.

Internet Access: Disable/Enable internet access (via IP release/renew).

USB Devices: Disable/Enable the use of USB storage devices.

III. System Maintenance & Optimization (Options 27-28, 61-63) 🧹🚀
Tools to help maintain system performance and cleanliness.

Clean Temporary Files: Delete system temporary files.

Clean Registry: Clean some registry entries related to recently used file lists.

Optimize for Performance: Optimize the system for maximum performance (via power plan).

Optimize for Energy Saving: Optimize the system for energy efficiency (via power plan).

Clear DNS Cache: Clear the Domain Name System (DNS) resolver cache.

IV. User & Network Management (Options 29-31, 49-56, 69) 👤🌐
Control over user accounts and network settings.

User Accounts: Disable/Enable user accounts (Guest and Administrator).

Manage User Accounts: Open the user account management tool.

Password Policies: Change some password policies (hide last user name, password expiry warning).

Encrypt/Decrypt Folder (EFS): Encrypt/Decrypt a specific folder (C:\SecureFolder).

Block/Unblock IP: Block/Unblock a specific IP address (hardcoded in the code).

Change DNS to Google: Change DNS settings for "Ethernet" and "Wi-Fi" interfaces to Google Public DNS.

Reset Network Settings: Reset Internet Protocol configuration and Winsock.

Monitor User Sessions: View active user sessions.

V. System Operations & Administration (Options 32-40, 45-47, 64-68, 70-71) 💻📊
Control over core processes, services, and general system behaviors.

Disable/Enable System Services: Disable/Enable Windows Defender and Windows Update services (a dangerous operation).

Restart/Shutdown System: Perform an immediate system restart or shutdown.

System Security Scan: Start the Microsoft Support Emergency Response Tool (MSERT).

Create Restore Point: Create a manual system restore point.

Restore System from Point: Open the System Restore window.

Manage System Processes: Open Task Manager.

Disable/Enable Sleep Feature: Disable/Enable the system's sleep feature.

Change Power Policies: Open power options window.

Manage Startup Programs: Open System Configuration (msconfig) window.

Generate Health Report: Initiate system performance health report generation.

Scan System Files (SFC): Start System File Checker scan.

Check Disk Errors: Initiate disk error check.

Open Performance Monitor: Open the Performance Monitor tool.

Open Security Policy: Open the Local Security Policy editor.

Change Region Settings: Open Region and Language settings.

VI. System Customization & Settings (Options 41-44, 72-73) 🎨⚙️
Customize appearance and certain behaviors.

Disable/Enable Printing: Disable/Enable the print spooler service.

Change/Reset Desktop Wallpaper: Change desktop wallpaper to a default image or reset it.

Disable Notifications: Disable the system's Notification Center.

Backup System Settings: Create a backup of key registry settings.

VII. Advanced Security Features (Options 57-60) 🛡️
Enable Event Logging: Enable event logging for Application, Security, and System.

Disable Untrusted Programs: Enable code integrity checks to identify trusted programs.

Create Firewall Rule: Create a firewall rule to block TCP ports 80-90.

Run Security Scan: Start the Microsoft Support Emergency Response Tool (MSERT).

VIII. Additional User Interface Features 🖥️
System Snapshots: Ability to create a comprehensive snapshot of the system's state (registry, services, processes, network info).

Safe Mode: Provides instructions on how to boot the system into Safe Mode.

Custom Command Execution: An input field to run custom CMD commands directly.

Theme Toggle (Dark Mode/Light Mode): Switch the user interface appearance between light and dark themes.

Status Bar: Displays information about the tool's status (Admin Mode, Safe Mode).

File Restoration: Feature to restore essential system tools (like Task Manager) from a user-selected source file.

Requirements 📋
Operating System: Windows

Administrator Privileges: The tool requires running with administrator privileges to access critical system functionalities.

How to Use ▶️
Run as Administrator: The executable file (.exe) must be run as an administrator. The tool will display an error message and exit if not run with sufficient privileges.

Security Warning: Upon first launch, a warning window will appear explaining the dangerous nature of the tool. Accept to proceed.

Main Interface:

Options List: Contains 73 different options for system management.

Status Bar: Shows whether you are in Admin Mode and Safe Mode.

"Execute Selected Action" Button: To perform the selected option from the list.

Command Input Field & "Run" Button: To execute custom CMD commands.

"Take Snapshot" Button: To create a current system snapshot in a new folder.

"Toggle Theme" Button: To switch between light and dark themes.

"Safe Mode" Button: To display instructions on how to enter Safe Mode.

"Help" Button: To display information about the tool and its version.

"Exit" Button: To close the tool.

Important Notes 📝
Dangerous Operations: Some operations (e.g., deleting Task Manager) require additional confirmation due to their critical nature.

File Restoration: Restoration options (e.g., restoring Task Manager) require you to select a source file present on your system.

System Snapshots: It is highly recommended to create a system snapshot before executing any changes that might affect system stability.

Warnings and Risks ⚠️
Data Loss or System Instability: Some operations, especially "PERMANENTLY delete!", can render your system unusable. Use these options with extreme caution and at your own risk.

Administrator Privileges: Administrator privileges ensure the tool has the capability to make extensive changes to your system. Be aware of what you are doing before executing.

Reliance on Fixed Paths: Some functions rely on fixed Windows system file paths (e.g., C:\Windows\System32\Taskmgr.exe). They may not function correctly if these paths are altered or if the files are missing.

Safe Mode: Users are encouraged to consider running the tool in system Safe Mode when performing particularly sensitive operations.

Development & Debugging 👨‍💻
Development Environment: The tool was developed using the Windows API.

Libraries: The tool relies on several standard Windows libraries (e.g., advapi32.lib, user32.lib, shell32.lib, etc.).

Administrator Check: Administrator privileges are checked at startup to prevent unauthorized use.

Error Handling: The tool includes simple mechanisms for reporting errors and successes via messa
