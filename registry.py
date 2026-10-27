import re
# ============================
# Registry hive normalization rules
# ============================
HIVE_RULES = [
    (re.compile(r"HKEY_LOCAL_MACHINE|HKLM", re.IGNORECASE), "HKLM"),
    (re.compile(r"HKEY_CURRENT_USER|HKCU", re.IGNORECASE), "HKCU"),
    (re.compile(r"HKEY_CLASSES_ROOT|HKCR", re.IGNORECASE), "HKCR"),
    (re.compile(r"HKEY_USERS|HKU", re.IGNORECASE), "HKU"),
    (re.compile(r"HKEY_CURRENT_CONFIG|HKCC", re.IGNORECASE), "HKCC"),
]


SID_TOKEN_RE = re.compile(r"^S-1-\d+(?:-\d+)+(?:_CLASSES)?$", re.IGNORECASE)
GUID_TOKEN_RE = re.compile(r"^\{?[A-F0-9]{8}-[A-F0-9]{4}-[A-F0-9]{4}-[A-F0-9]{4}-[A-F0-9]{12}\}?$", re.IGNORECASE)

def registry_part_token(part):
    part = (part or "").strip()
    if not part:
        return "<NONE>"
    upper = part.upper()
    if SID_TOKEN_RE.match(part):
        return "<SID_CLASSES>" if upper.endswith("_CLASSES") else "<SID>"
    if GUID_TOKEN_RE.match(part):
        return "<GUID>"
    if re.match(r"^APPX[A-Z0-9]+$", upper):
        return "<APPX_PACKAGE>"
    return f"<{upper}>"

# ============================
# Action category rules
# ============================
CATEGORY_RULES = [

    # ===== Tier 1: Auto-Start Registration =====
    (re.compile(r"\\CurrentVersion\\Run(?:Once)?(\\|$)", re.IGNORECASE), "RUN"),
    (re.compile(r"\\Explorer\\StartupApproved\\Run", re.IGNORECASE), "RUN_APPROVED"),
    (re.compile(r"\\(CurrentVersion\\Schedule\\TaskCache|Tasks)", re.IGNORECASE), "TASK"),
    (re.compile(r"\\System\\(CurrentControlSet|ControlSet\d+)\\Services", re.IGNORECASE), "SERVICE"),
    (re.compile(r"\\CurrentVersion\\Winlogon", re.IGNORECASE), "WINLOGON"),

    # ===== Tier 2: Execution Redirection =====
    (re.compile(r"\\Image File Execution Options\\", re.IGNORECASE), "IFEO"),
    (re.compile(r"\\App Paths\\", re.IGNORECASE), "APP_PATH"),
    (re.compile(r"\\CLSID\\.*\\(InprocServer32|LocalServer32)", re.IGNORECASE), "COM"),
    (re.compile(r"\\Shell\\Open\\Command", re.IGNORECASE), "SHELL_CMD"),
    (re.compile(r"\\Software\\Classes\\\.(exefile|comfile|batfile|cmdfile|scrfile|piffile|[^\\]+)", re.IGNORECASE), "FILE_ASSOC"),

    # ===== Tier 3: Implicit Code Loading =====
    (re.compile(r"\\AppInit_DLLs", re.IGNORECASE), "APPINIT"),
    (re.compile(r"\\Print\\Monitors", re.IGNORECASE), "PRINT_MONITOR"),
    (re.compile(r"\\CurrentControlSet\\Control\\Session Manager\\KnownDLLs", re.IGNORECASE), "KNOWNDLLS"),

    # ===== Tier 4: User Activity Tracing =====
    (re.compile(r"\\UserAssist", re.IGNORECASE), "USERASSIST"),
    (re.compile(r"\\MUICache", re.IGNORECASE), "MUICACHE"),
    (re.compile(r"\\RecentDocs", re.IGNORECASE), "RECENTDOCS"),
    (re.compile(r"\\ComDlg32", re.IGNORECASE), "COMDLG"),
    (re.compile(r"\\Control\\Session Manager\\AppCompatCache", re.IGNORECASE), "SHIMCACHE"),

    # ===== Tier 5: Storage & Device Enumeration =====
    (re.compile(r"\\MountPoints2", re.IGNORECASE), "MOUNT"),
    (re.compile(r"\\ShellBags|\\BagMRU", re.IGNORECASE), "SHELLBAG"),
    (re.compile(r"(\\Enum\\(USBSTOR|PCI|USB|ACPI|SWD|DISPLAY|ROOT|HDAUDIO|STORAGE|SCSI|HID|BTH|HTREE|FDC)|HARDWARE\\(DEVICEMAP|DESCRIPTION))", re.IGNORECASE), "DEVICE"),
    (re.compile(r"\\(DriverDatabase|BCD00000000|DRIVERS)", re.IGNORECASE), "DEVICE"),

    # ===== Tier 6: Security Control Configuration =====
    (re.compile(r"\\Control\\Lsa", re.IGNORECASE), "LSA"),
    (re.compile(r"\\Software\\Policies\\", re.IGNORECASE), "POLICY"),
    (re.compile(r"\\CurrentControlSet\\Policies\\", re.IGNORECASE), "POLICY"),
    (re.compile(r"\\FirewallRules", re.IGNORECASE), "FIREWALL"),
    (re.compile(r"\\(SAM($|\\)|SECURITY($|\\)|WPA)", re.IGNORECASE), "SECURITY"),

    # ===== Tier 7: Network Trust Configuration =====
    (re.compile(r"\\ZoneMap", re.IGNORECASE), "ZONEMAP"),
    (re.compile(r"\\Internet Settings", re.IGNORECASE), "SETTINGS"),

    # ===== Tier 8: Shell Behavior Customization =====
    (re.compile(r"\\Explorer\\(Advanced|TrayNotify|Streams)", re.IGNORECASE), "SHELL_CONFIG"),

    # ===== Tier 9: Core System Parameterization =====
    (re.compile(r"^\\REGISTRY\\A\\", re.IGNORECASE), "SYSTEM_VIRTUAL"),
    (re.compile(r"\\Control Panel($|\\)", re.IGNORECASE), "USER_UI"),
    (re.compile(r"\\(Environment|Console|Volatile Environment|GameConfigStore|Keyboard Layout|EUDC|OSDATA|Input)", re.IGNORECASE), "SYSTEM_ENV"),
    (re.compile(r"\\Control\\(Power|Hvsi|Nls|ProductOptions|Cryptography|TimeZoneInformation|WMI|SafeBoot|MUI|Class|DeviceClasses|ContentIndex|Session Manager|AppCertDlls|Video|FileSystem|SecurityProviders|CI|PriorityControl|StateSeparation|DevQuery|ComputerName|Srp|Notifications|GraphicsDrivers|MiniNT|Error Message Instrument|PortableOperatingSystem|DeviceGuard|Terminal Server|EAS|SCMConfig|CrashControl|MediaCategories|ProfileList|WDI|Els|NetworkUxManager|Compression|Nsi|SystemInformation|ContainerId|LeapSecondInformation|Ubpm|EmulateWorkerSession|WindowsSysPartDevice|hivelist|NetDiagFx|WaitToKillServiceTimeout|WinInit|NetworkProvider|CloudDomainJoin|FeatureManagement|{[A-F0-9-]+})", re.IGNORECASE), "SYSTEM_CONFIG"),
    (re.compile(r"\\(SYSTEM|System)\\CurrentControlSet($|\\)", re.IGNORECASE), "SYSTEM_CONFIG"),
    (re.compile(r"\\SYSTEM\\Setup", re.IGNORECASE), "SYSTEM_SETUP"),
    (re.compile(r"\\Platform\\(DeviceTargetingInfo|MTPTargetingInfo)", re.IGNORECASE), "SYSTEM_CONFIG"),
    (re.compile(r"\\(%DiagtrackRegistryRoot%|EventLog-)", re.IGNORECASE), "SYSTEM_CONFIG"),

    # ===== Tier 10: Network Stack Configuration =====
    (re.compile(r"\\Tcpip\\Parameters\\Interfaces", re.IGNORECASE), "NET_CONFIG"),
    (re.compile(r"\\Network", re.IGNORECASE), "NETWORK_PROFILE"),

    # ===== Tier 11: System Object Resolution =====
    (re.compile(r"\\(CLSID|Interface|TypeLib|ProxyStubClsid32|Folder|Directory|Installer|AllFilesystemObjects|txtfile|Assemblies|Instance|InitPropertyBag|PropertyBag|Media Type|DirectShow|exefile|wordpad\.exe|notepad\.exe|PackagedCom|Kind\.program|Unknown|Results|Filter|Applications|WaaS|AppID|ActivatableClasses|SystemFileAssociations|PROTOCOLS|Extensions|Unmarshalers|DelegateFolders|Msi\.Package|WScript\.Shell|Microsoft\.PowerShellScript\.1|MSEdgeHTM|WOW6432Node|MediaFoundation|AudioEngine|LibraryFolder|UserLibraryFolder|lnkfile|docxfile|htmlfile|chm\.file|CompressedFolder|ExplorerCLSIDFlags|Search|OneCoreContracts|SyncCommands|Launcher\.AllAppsDesktopApplication|VisualStudio\.sln|IE\.AssocFile|ChromeHTML|ProcMon\.Logfile|Word\.Document|RStudio\.Rproj|xlsxfile|docxfile|pdffile|batfile|cmdfile|piffile|vbsfile|wshfile|textfile|LDAP|Chrome|roblox|Steam|Drive|Printers|DesktopBackground|JScript|script|file|http|https|Kind\.Document|Content Type|Microsoft\.Windows\.Explorer|FhSearchPHLibrary|IEPH|MCSF|CellularAPI|microsoft-edge|AutoGenerated|OneCoreContracts|NetServer|NetShare|InternetShortcut|PKOFile|WinNTNamespace|dllfile|Excel\.CSV|Excel\.Sheet|ShockwaveFlash|AcroPDF|XEV\.GenericApp|FirefoxHTML|VMwareHostOpen|Outlook\.Search|Outlook\.Application|RWorkspace|MSEdge|Briefcase|AcroDUMMY|VideoLAN|RealPlayer|AgControl|SWCtl|SyncCommands|MajorDoc|EnterpriseModernAppManagement|CuratedTileCollections|MSXML2|\.|\*)", re.IGNORECASE), "INFRA"),

    # ===== Tier 12: Application Scope Configuration =====
    (re.compile(r"\\(\.DEFAULT|S-1-5-18|S-1-5-19|S-1-5-20|\(Default\))", re.IGNORECASE), "ROOT_ACCESS"),
    (re.compile(r"^(HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKEY_CLASSES_ROOT|HKEY_USERS|HKLM|HKCU|HKCR|HKCC|HKU)(\\SOFTWARE|\\SYSTEM|\\)?(\\?)$", re.IGNORECASE), "ROOT_ACCESS"),
    (re.compile(r"\\(AppEvents|MIME\\Database)", re.IGNORECASE), "APP_MICROSOFT"), 
    (re.compile(r"\\Software\\(Microsoft|Policies)", re.IGNORECASE), "APP_MICROSOFT"),
    (re.compile(r"\\Software\\[^\\]+", re.IGNORECASE), "APP_VENDOR"),
]

# ============================
# Main normalization function
# ============================
def standardize_registry_keys(registry_key, mapping_collector=None):
    if not isinstance(registry_key, str) or not registry_key.strip():
        return "<NON_KEY>/<NONE>/<NONE>/<NONE>/<NONE>"

    # 1. Normalize case, separators, and surrounding whitespace.
    raw_key = registry_key.lower().replace("/", "\\").strip()
    # Remove the WOW6432Node segment and collapse repeated separators.
    key = raw_key.lstrip("\\").replace("wow6432node\\", "")
    key = re.sub(r'\\+', r'\\', key)
    
    # 2. Identify the original hive before aligning aliases.
    orig_hive = "OTHER"
    # Use the first matching hive rule.
    for p, t in HIVE_RULES:
        if p.search(raw_key):
            orig_hive = t
            break

    # 3. Align equivalent registry paths across hive prefixes.
    hive_token = orig_hive
    is_alias_target = False
    
    # Alias group A: Classes, FileExts, and PackagedCom paths
    if any(k in key for k in ["software\\classes", "hkcr", "explorer\\fileexts", "packagedcom"]):
        hive_token = "HK_CLASSES_ALIAS"
        is_alias_target = True
        key = key.replace("hkey_current_user\\", "").replace("hkcu\\", "") \
                 .replace("hkey_local_machine\\", "").replace("hklm\\", "") \
                 .replace("software\\classes\\", "").replace("hkey_classes_root\\", "") \
                 .replace("hkcr\\", "").replace("software\\microsoft\\windows\\currentversion\\explorer\\fileexts\\", "") \
                 .replace("packagedcom\\", "")
        key = re.sub(r"^(clsid|appid|interface|typelib)", "COM_OBJECT", key, flags=re.I)
        
    # Alias group B: Microsoft software paths, including policy settings
    elif "software\\microsoft" in key or "software\\policies\\microsoft" in key:
        hive_token = "HK_SOFTWARE_MS_ALIAS"
        # Remove the supported Microsoft software and policy prefixes.
        key = key.replace("hklm\\software\\microsoft\\", "").replace("hkcu\\software\\microsoft\\", "") \
                 .replace("hklm\\software\\policies\\microsoft\\", "").replace("hkcu\\software\\policies\\microsoft\\", "") \
                 .replace("software\\microsoft\\", "").replace("software\\policies\\microsoft\\", "")
    else:
        # Strip supported hive prefixes from paths outside the alias groups.
        if "hklm\\" in key: hive_token = "HKLM"; key = key.replace("hklm\\", "")
        elif "hkcu\\" in key: hive_token = "HKCU"; key = key.replace("hkcu\\", "")
        elif "hku\\" in key: hive_token = "HKU"; key = key.replace("hku\\", "")
        elif "hkey_local_machine\\" in key: hive_token = "HKLM"; key = key.replace("hkey_local_machine\\", "")

    # Extract tokens for the first three remaining path components.
    raw_parts = [p for p in key.split('\\') if p]
    obj1 = registry_part_token(raw_parts[0]) if len(raw_parts) > 0 else "<ROOT>"
    obj2 = registry_part_token(raw_parts[1]) if len(raw_parts) > 1 else "<NONE>"
    obj3 = registry_part_token(raw_parts[2]) if len(raw_parts) > 2 else "<NONE>"

    # 4. Use a shared action token for aligned aliases; otherwise match a category.
    if is_alias_target or hive_token == "HK_SOFTWARE_MS_ALIAS":
        action_token = "<ALIGNED_ACTION>"
    else:
        action_token = "<OTHER_ACTION>"
        for p, t in CATEGORY_RULES:
            if p.search(raw_key): action_token = f"<{t}>"; break

    # 5. Terminal Payload
    terminal_name = "<NONE>"
    if len(raw_parts) > 0:
        term = raw_parts[-1]
        terminal_name = f"<{term}>"

    # 6. Assemble six fields: hive, three object tokens, action, and terminal name.
    normalized = f"<{hive_token}>/{obj1}/{obj2}/{obj3}/{action_token}/{terminal_name}"

    if mapping_collector is not None:
        mapping_collector.append((registry_key, normalized))
    return normalized
