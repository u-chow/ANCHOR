import os
import re

# ============================
# Map file extensions to semantic tokens.
# ============================
replacement_rules = [
    # CORE FILE TYPE RULES
    (re.compile(r"\.(exe|bin|msi|com|scr|cpl|gadget|jar|wsf)$", re.IGNORECASE), "<EXECUTABLE_FILE>"),
    (re.compile(r"\.(bat|ps1|vbs|js|sh|py|php|cmd|reg|ws|jse|vbe|pyw)$", re.IGNORECASE), "<SCRIPT_FILE>"),
    (re.compile(r"\.(jpg|jpeg|png|gif|bmp|tiff|ico|svg|webp|mp3|wav|flac|mp4|avi|mov|mkv|wmv)$", re.IGNORECASE), "<MEDIA_FILE>"),
    (re.compile(r"\.(ini|conf|json|xml|yaml|yml|pro|pri|qrc|toml|env|dockerfile|editorconfig)$", re.IGNORECASE), "<CONFIG_FILE>"),

    # 1. Documents, including office formats and e-books.
    (re.compile(r"\.(doc|docx|ppt|pptx|xls|xlsx|pdf|rtf|odt|csv|md|pages|numbers|key|epub|mobi)$", re.IGNORECASE), "<DOCUMENT_FILE>"),
    
    # 2. Executables; the rule is already included among the core file types above.
    
    # 3. System libraries, drivers, and related components.
    (re.compile(r"\.(dll|sys|mui|inf|cat|ocx|tlb|drv|ax|acm)$", re.IGNORECASE), "<LIBRARY_FILE>"),
    
    # 4. Scripts; the rule is already included among the core file types above.
    
    # 5. Source code in common programming languages.
    (re.compile(r"\.(h|hpp|c|cpp|cc|qml|pyi|java|cs|go|rs|swift|kt|rb|lua|pl|sql|ts|tsx|jsx)$", re.IGNORECASE), "<SOURCE_CODE_FILE>"),
    
    # 6. Web documents and stylesheets.
    (re.compile(r"\.(html|htm|css|js|jsp|asp|aspx|php|less|scss)$", re.IGNORECASE), "<WEB_FILE>"),
    
    # 7. Shortcuts, including URL shortcuts.
    (re.compile(r"\.(lnk|url|pif)$", re.IGNORECASE), "<SHORTCUT_FILE>"),
    
    # 8. Temporary files, backups, and crash dumps.
    (re.compile(r"\.(temp|bak|tmp|old|orig|dmp|err|crash)$", re.IGNORECASE), "<TEMP_FILE>"),
    
    # 9. Media; the rule is already included among the core file types above.
    
    # 10. Archives, compressed files, and platform package formats.
    (re.compile(r"\.(zip|rar|7z|tar|gz|bz2|xz|iso|dmg|pkg|deb|rpm)$", re.IGNORECASE), "<COMPRESSED_FILE>"),
    
    # 11. Configuration; the rule is already included among the core file types above.
    
    # 12. Distinguish log files from plain text files.
    (re.compile(r"\.log\d*$", re.IGNORECASE), "<LOG_FILE>"),
    (re.compile(r"\.txt$", re.IGNORECASE), "<TEXT_FILE>"),
    
    # 13. Metadata and version-control artifacts.
    (re.compile(r"(\.git|\.pyc|\.pyd|\.identifier|\.DS_Store|\.gitignore|\.svn|\.hg)$", re.IGNORECASE), "<METADATA_FILE>"),

    # 14. Database and structured data files.
    (re.compile(r"\.(db|sqlite|sqlite3|mdb|accdb|dbf|dat|sav)$", re.IGNORECASE), "<DATABASE_FILE>"),

    # 15. Fonts.
    (re.compile(r"\.(ttf|otf|woff|woff2|eot|fon)$", re.IGNORECASE), "<FONT_FILE>"),

    # 16. Certificates, keys, and other security artifacts.
    (re.compile(r"\.(cer|crt|pem|pfx|p12|key|pub|der|csr|crl|p7b)$", re.IGNORECASE), "<SECURITY_FILE>"),

    # 17. Virtual machine disks and appliance images.
    (re.compile(r"\.(vmdk|vhd|vhdx|ova|ovf|vdi|img)$", re.IGNORECASE), "<VIRTUAL_FILE>"),

    # 18. Email messages and mailbox data.
    (re.compile(r"\.(msg|eml|pst|ost|edb)$", re.IGNORECASE), "<EMAIL_FILE>"),

    # 19. System policies and administrative templates.
    (re.compile(r"\.(pol|adm|admx|adml|msc)$", re.IGNORECASE), "<POLICY_FILE>"),
]

# ============================
# Map folder paths to semantic tokens.
# Match Startup paths before broader ProgramData rules.
# ============================
folder_replacement_rules = [
    # [1] Normalize device volume prefixes.
    (re.compile(r"[/\\]?device[/\\]harddiskvolume\d+", re.IGNORECASE), "<VOLUME>"),

    # [2] Map environment-variable aliases to their folder roles.
    # Handle specific compound names before broader variable rules.
    (re.compile(r"%COMMONPROGRAMFILES\(X86\)%", re.IGNORECASE), "<PROGRAM_FOLDER_X86>/<COMMON>"),
    (re.compile(r"%COMMONPROGRAMFILES%", re.IGNORECASE), "<PROGRAM_FOLDER>/<COMMON>"),
    (re.compile(r"%PROGRAMFILES\(X86\)%", re.IGNORECASE), "<PROGRAM_FOLDER_X86>"),
    (re.compile(r"%PROGRAMFILES%", re.IGNORECASE), "<PROGRAM_FOLDER>"),
    (re.compile(r"%PUBLIC%", re.IGNORECASE), "<PUBLIC_FOLDER>"),
    (re.compile(r"%SYSTEMDRIVE%", re.IGNORECASE), "<SYSTEM_DRIVE>"),

    # ===========================================================
    # STARTUP FOLDERS: match before generic user and ProgramData paths.
    # ===========================================================
    (re.compile(r"C:/Users/[^/]+/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup",
                re.IGNORECASE), "<STARTUP_FOLDER>"),

    (re.compile(r"C:/ProgramData/Microsoft/Windows/Start Menu/Programs/Startup",
                re.IGNORECASE), "<STARTUP_FOLDER>"),

    # ===========================================================
    # SPECIFIC USER SUBFOLDERS (must run before generic C:/Users/<user>)
    # ===========================================================
    (re.compile(r"C:/Users/[^/]+/AppData/Local/Microsoft/Windows/FileHistory", re.IGNORECASE),
     "<FH_FOLDER>"),
    (re.compile(r"C:/Users/[^/]+/AppData/Local/Temp", re.IGNORECASE), "<TEMP_FOLDER>"),
    (re.compile(r"C:/Users/[^/]+/AppData/Roaming", re.IGNORECASE), "<APPDATA_ROAMING>"),
    (re.compile(r"C:/Users/[^/]+/AppData/Local", re.IGNORECASE), "<APPDATA_LOCAL>"),

    # ===========================================================
    # USER FOLDERS
    # ===========================================================
    (re.compile(r"%USERPROFILE%", re.IGNORECASE), "<USER_FOLDER>"),

    (re.compile(r"C:/Users/Public", re.IGNORECASE), "<PUBLIC_FOLDER>"),
    (re.compile(r"C:/Users/[^/]+", re.IGNORECASE), "<USER_FOLDER>"),
    (re.compile(r"C:/Documents and Settings/[^/]+", re.IGNORECASE), "<USER_FOLDER>"),

    # ===========================================================
    # APPDATA (Roaming / Local)
    # ===========================================================
    (re.compile(r"%APPDATA%", re.IGNORECASE), "<APPDATA_ROAMING>"),
    (re.compile(r"%LOCALAPPDATA%", re.IGNORECASE), "<APPDATA_LOCAL>"),

    (re.compile(r"C:/Users/[^/]+/AppData/Roaming", re.IGNORECASE), "<APPDATA_ROAMING>"),
    (re.compile(r"C:/Users/[^/]+/AppData/Local", re.IGNORECASE), "<APPDATA_LOCAL>"),

    # FileHistory
    (re.compile(r"C:/Users/[^/]+/AppData/Local/Microsoft/Windows/FileHistory", re.IGNORECASE),
     "<FH_FOLDER>"),

    # ===========================================================
    # TEMP FOLDERS
    # ===========================================================
    (re.compile(r"%TEMP%", re.IGNORECASE), "<TEMP_FOLDER>"),
    (re.compile(r"%TMP%", re.IGNORECASE), "<TEMP_FOLDER>"),
    (re.compile(r"C:/Users/[^/]+/AppData/Local/Temp", re.IGNORECASE), "<TEMP_FOLDER>"),
    (re.compile(r"C:/Windows/Temp", re.IGNORECASE), "<TEMP_FOLDER>"),

    # ===========================================================
    # SYSTEM ROOT & WINDOWS
    # ===========================================================
    (re.compile(r"%SYSTEMROOT%", re.IGNORECASE), "<SYSTEM_FOLDER>"),
    (re.compile(r"%WINDIR%", re.IGNORECASE), "<SYSTEM_FOLDER>"),

    (re.compile(r"C:/Windows/System32", re.IGNORECASE), "<SYSTEM_FOLDER>"),
    (re.compile(r"C:/Windows/SysWOW64", re.IGNORECASE), "<SYSTEM_FOLDER>"),
    (re.compile(r"C:/Windows", re.IGNORECASE), "<SYSTEM_FOLDER>"),

    # ===========================================================
    # PROGRAM FILES
    # ===========================================================
    (re.compile(r"%PROGRAMFILES%", re.IGNORECASE), "<PROGRAM_FOLDER>"),
    (re.compile(r"%PROGRAMFILES\(X86\)%", re.IGNORECASE), "<PROGRAM_FOLDER_X86>"),

    (re.compile(r"C:/Program Files \(x86\)", re.IGNORECASE), "<PROGRAM_FOLDER_X86>"),
    (re.compile(r"C:/Program Files", re.IGNORECASE), "<PROGRAM_FOLDER>"),

    # ===========================================================
    # PROGRAMDATA
    # ===========================================================
    (re.compile(r"%ALLUSERSPROFILE%", re.IGNORECASE), "<PROGRAM_DATA>"),
    (re.compile(r"C:/ProgramData", re.IGNORECASE), "<PROGRAM_DATA>"),

    # ===========================================================
    # SYSTEM DRIVE
    # ===========================================================
    (re.compile(r"%SYSTEMDRIVE%", re.IGNORECASE), "<SYSTEM_DRIVE>"),

    # ===========================================================
    # FILE HISTORY (External Drive)
    # ===========================================================
    (re.compile(r"%FHDRIVE%", re.IGNORECASE), "<FH_FOLDER>"),
    (re.compile(r"%FHBACKUPDIR%", re.IGNORECASE), "<FH_FOLDER>"),

    # ===========================================================
    # OTHER DRIVES
    # ===========================================================
    (re.compile(r"[D-Z]:/", re.IGNORECASE), "<OTHER_DRIVE_FOLDER>/"),

    # ===========================================================
    # NETWORK SHARES
    # ===========================================================
    (re.compile(r"//[a-zA-Z0-9._-]+/", re.IGNORECASE), "<NETWORK_SHARE_FOLDER>/"),
]


# ============================
# STANDARDIZE FUNCTION
# ============================
def standardize_file_path_and_name(file_path, mapping_collector=None):
    if not isinstance(file_path, str):
        return ""

    original_val = file_path
    path = file_path.replace("\\", "/").strip()
    path = re.sub(r'/+', '/', path)

    # 2) Accept supported drive, variable, root, device, and volume prefixes.
    is_valid = re.match(r"^[A-Za-z]:/|^%[A-Za-z_()0-9]+%|^/|^device/|^<VOLUME>", path, re.I)

    if not is_valid:
        normalized_res = "<NON_FILE_PATH>"
    else:
        # 3) Apply folder substitutions to the complete path.
        normalized = path
        for pattern, replacement in folder_replacement_rules:
            normalized = pattern.sub(replacement, normalized)

        # 4) Identify the normalized root, including device volumes.
        ROOT_TOKENS = [
            "<STARTUP_FOLDER>", "<USER_FOLDER>", "<APPDATA_LOCAL>",
            "<APPDATA_ROAMING>", "<TEMP_FOLDER>", "<SYSTEM_FOLDER>",
            "<PROGRAM_FOLDER>", "<PROGRAM_FOLDER_X86>", "<PROGRAM_DATA>",
            "<OTHER_DRIVE_FOLDER>", "<NETWORK_SHARE_FOLDER>", "<VOLUME>", "<PUBLIC_FOLDER>"
        ]

        root_token = None
        remaining_path = ""
        for token in ROOT_TOKENS:
            if normalized.startswith(token):
                root_token = token
                remaining_path = normalized[len(token):].strip("/")
                break

        # 5) Classify the original basename using the first matching rule.
        file_name = os.path.basename(path)
        file_name_token = "<OTHER_FILE>"
        for pattern, replacement in replacement_rules:
            if pattern.search(file_name):
                file_name_token = replacement
                break

        # Preserve the complete basename as an additional tag.
        full_file_name_tag = f"<{file_name}>"

        # 6) Combine root, optional subfolder, file type, and complete basename.
        if root_token:
            parts = [p for p in remaining_path.split("/") if p]
            if len(parts) > 1:
                # Format: root / first subfolder / file type / complete basename.
                sub_dir = parts[0].upper()
                normalized_res = f"{root_token}/<{sub_dir}>/{file_name_token}/{full_file_name_tag}"
            else:
                # Format: root / file type / complete basename.
                normalized_res = f"{root_token}/{file_name_token}/{full_file_name_tag}"
        else:
            # Format: generic path / file type / complete basename.
            normalized_res = f"<FILE_PATH>/{file_name_token}/{full_file_name_tag}"

    if mapping_collector is not None:
        mapping_collector.append((original_val, normalized_res))

    return normalized_res
