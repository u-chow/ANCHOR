import ntpath
import re

from file import standardize_file_path_and_name


FIRST_TOKEN_RE = re.compile(r'^\s*(?:"([^"]+)"|(\S+))(.*)$')
PATH_ARG_RE = re.compile(r'"((?:[A-Za-z]:\\|%[A-Za-z0-9_()]+%)[^"]+)"|((?:[A-Za-z]:\\|%[A-Za-z0-9_()]+%)[^\s"]+)')
URL_RE = re.compile(r"https?://\S+", re.IGNORECASE)
UNC_PATH_ARG_RE = re.compile(r'"(\\\\[^"]+)"|(\\\\[^\s"]+)')
IPV4_RE = re.compile(r"(?<![\w.])((?:\d{1,3}\.){3}\d{1,3})(?![\w.])")

POWERSHELL_NAMES = {"powershell.exe", "pwsh.exe"}
CMD_NAMES = {"cmd.exe"}

ARG_FILE_TAGS = (
    "<COMPRESSED_FILE>",
    "<DOCUMENT_FILE>",
    "<EXECUTABLE_FILE>",
    "<SCRIPT_FILE>",
    "<CONFIG_FILE>",
    "<DATABASE_FILE>",
    "<LIBRARY_FILE>",
    "<LOG_FILE>",
    "<MEDIA_FILE>",
    "<SECURITY_FILE>",
    "<TEXT_FILE>",
    "<TEMP_FILE>",
)


def _extract_executable(commandline: str) -> tuple[str, str]:
    match = FIRST_TOKEN_RE.match(commandline)
    if not match:
        return commandline.strip(), ""
    executable = match.group(1) or match.group(2) or ""
    remainder = (match.group(3) or "").strip()
    return executable.strip(), remainder


def _process_token(executable: str) -> str:
    basename = ntpath.basename(executable.strip().strip('"')).lower()
    if not basename:
        basename = executable.strip().lower()
    return basename or "<UNKNOWN_PROCESS>"


def _collapse_path_arg(path_text: str) -> str | None:
    standardized = standardize_file_path_and_name(path_text)
    if standardized == "<NON_FILE_PATH>":
        return None
    for tag in ARG_FILE_TAGS:
        if tag in standardized:
            return f"<ARG_{tag.strip('<>')}>"
    if standardized.startswith("<"):
        root = standardized.split("/", 1)[0]
        return f"<ARG_{root.strip('<>')}>"
    return "<ARG_PATH>"


def _cmdcaliper_path_placeholder(path_text: str) -> str:
    standardized = standardize_file_path_and_name(path_text)
    if standardized == "<NON_FILE_PATH>":
        return "<PATH>"
    if "<NETWORK_SHARE_FOLDER>" in standardized:
        return "<NETWORK_PATH>"
    if "<TEMP_FILE>" in standardized or "<TEMP_FOLDER>" in standardized:
        return "<TEMP_PATH>"
    for tag in ARG_FILE_TAGS:
        if tag in standardized:
            return tag
    root = standardized.split("/", 1)[0]
    root_map = {
        "<SYSTEM_FOLDER>": "<SYSTEM_PATH>",
        "<PROGRAM_FOLDER>": "<PROGRAM_PATH>",
        "<PROGRAM_FOLDER_X86>": "<PROGRAM_PATH>",
        "<PROGRAM_DATA>": "<PROGRAM_DATA_PATH>",
        "<USER_FOLDER>": "<USER_PATH>",
        "<PUBLIC_FOLDER>": "<PUBLIC_PATH>",
        "<APPDATA_LOCAL>": "<APPDATA_PATH>",
        "<APPDATA_ROAMING>": "<APPDATA_PATH>",
        "<OTHER_DRIVE_FOLDER>": "<OTHER_DRIVE_PATH>",
        "<VOLUME>": "<VOLUME_PATH>",
    }
    return root_map.get(root, "<PATH>")


def _argument_features(remainder: str) -> list[str]:
    features: list[str] = []
    for match in PATH_ARG_RE.finditer(remainder):
        raw_path = match.group(1) or match.group(2) or ""
        feature = _collapse_path_arg(raw_path)
        if feature and feature not in features:
            features.append(feature)
        if len(features) >= 3:
            break
    if URL_RE.search(remainder) and "<ARG_URL>" not in features:
        features.append("<ARG_URL>")
    return features


def _replace_path_like_args(text: str, replacer) -> str:
    def _sub(match: re.Match[str]) -> str:
        raw_path = match.group(1) or match.group(2) or ""
        return replacer(raw_path)

    text = PATH_ARG_RE.sub(_sub, text)
    text = UNC_PATH_ARG_RE.sub(_sub, text)
    return text


def _replace_ipv4(text: str) -> str:
    def _sub(match: re.Match[str]) -> str:
        raw_ip = match.group(1)
        octets = raw_ip.split(".")
        try:
            if any(int(part) > 255 for part in octets):
                return raw_ip
            if raw_ip.startswith(("10.", "127.", "192.168.")):
                return "<PRIVATE_IP>"
            if raw_ip.startswith("172."):
                second = int(octets[1])
                if 16 <= second <= 31:
                    return "<PRIVATE_IP>"
            return "<PUBLIC_IP>"
        except ValueError:
            return raw_ip

    return IPV4_RE.sub(_sub, text)


def _standardize_cmd_for_cmdcaliper(commandline: str, executable: str, remainder: str) -> str:
    normalized = f"{_process_token(executable)}"
    if remainder:
        rewritten = remainder
        rewritten = _replace_path_like_args(rewritten, _cmdcaliper_path_placeholder)
        rewritten = URL_RE.sub("<URL>", rewritten)
        rewritten = _replace_ipv4(rewritten)
        normalized = f"{normalized} {rewritten}"
    return re.sub(r"\s+", " ", normalized).strip()


def _powershell_signature(text_lower: str) -> list[str]:
    signatures: list[str] = []
    if "get-childitem" in text_lower and "select-object" in text_lower:
        signatures.append("<PS_GCI_ENUM>")
    elif "get-childitem" in text_lower:
        signatures.append("<PS_GCI>")

    if "downloadstring" in text_lower and "invoke-item" in text_lower:
        signatures.append("<PS_DOWNLOADSTRING_EXEC>")
    elif "downloadstring" in text_lower:
        signatures.append("<PS_DOWNLOADSTRING>")

    if "downloadfile" in text_lower:
        signatures.append("<PS_DOWNLOADFILE>")
    if "start-bitstransfer" in text_lower:
        signatures.append("<PS_BITSTRANSFER>")
    if "expand-archive" in text_lower:
        signatures.append("<PS_EXPAND_ARCHIVE>")
    if "set-itemproperty" in text_lower or "new-itemproperty" in text_lower:
        signatures.append("<PS_REG_MODIFY>")
    if "get-wmiobject" in text_lower:
        signatures.append("<PS_WMI_ENUM>")
    if "get-nettcpconnection" in text_lower and "minidump" in text_lower:
        signatures.append("<PS_MINIDUMP>")
    if re.search(r"\bping\b", text_lower):
        signatures.append("<PS_PING>")
    if re.search(r"\bdir\b", text_lower):
        signatures.append("<PS_DIR>")
    if "copy-item" in text_lower:
        signatures.append("<PS_COPY_ITEM>")
    if "out-file" in text_lower:
        signatures.append("<PS_OUT_FILE>")
    if "invoke-item" in text_lower and "<PS_DOWNLOADSTRING_EXEC>" not in signatures:
        signatures.append("<PS_INVOKE_ITEM>")
    if not signatures:
        signatures.append("<PS_GENERIC>")
    return signatures


def _cmd_signature(text_lower: str) -> list[str]:
    signatures: list[str] = []
    if "pnputil.exe" in text_lower:
        signatures.append("<CMD_PNPUTIL>")
    if "reg add" in text_lower:
        signatures.append("<CMD_REG_ADD>")
    if "curl.exe" in text_lower:
        signatures.append("<CMD_CURL>")
    if "cscript" in text_lower:
        signatures.append("<CMD_CSCRIPT>")
    if re.search(r"\bdir\b", text_lower):
        signatures.append("<CMD_DIR>")
    if re.search(r"\becho\b", text_lower):
        signatures.append("<CMD_ECHO>")
    if not signatures:
        signatures.append("<CMD_GENERIC>")
    return signatures


def _standardize_powershell(commandline: str, executable: str, remainder: str) -> str:
    tokens = ["<PROCESS>", f"<{_process_token(executable).upper()}>"]
    lower_text = commandline.lower()
    if re.search(r"(^|\s)-executionpolicy\s+bypass\b", lower_text):
        tokens.append("<EXEC_BYPASS>")
    elif "-executionpolicy" in lower_text:
        tokens.append("<EXEC_POLICY>")

    if re.search(r"(^|\s)-(enc|encodedcommand)\b", lower_text):
        tokens.append("<ENCODED>")
    elif re.search(r"(^|\s)-(c|command)\b", lower_text):
        tokens.append("<INLINE>")

    tokens.extend(_powershell_signature(lower_text))
    tokens.extend(_argument_features(remainder))
    return "/".join(tokens)


def _standardize_cmd(commandline: str, executable: str, remainder: str) -> str:
    tokens = ["<PROCESS>", f"<{_process_token(executable).upper()}>"]
    lower_text = commandline.lower()
    if re.search(r"(^|\s)/c(\s|$)", lower_text):
        tokens.append("<INLINE>")
    elif re.search(r"(^|\s)/k(\s|$)", lower_text):
        tokens.append("<KEEP_OPEN>")
    tokens.extend(_cmd_signature(lower_text))
    tokens.extend(_argument_features(remainder))
    return "/".join(tokens)


def _standardize_generic(executable: str, remainder: str) -> str:
    process_name = _process_token(executable)
    tokens = ["<PROCESS>", f"<{process_name.upper()}>"]
    tokens.extend(_argument_features(remainder))
    return "/".join(tokens)


def standardize_process_commandline(commandline, mapping_collector=None, profile: str = "default"):
    if not isinstance(commandline, str):
        return ""

    raw_text = commandline.strip()
    if not raw_text:
        return ""

    normalized_text = re.sub(r"\s+", " ", raw_text).strip()
    executable, remainder = _extract_executable(normalized_text)
    process_name = _process_token(executable)

    if profile == "cmdcaliper" and process_name in CMD_NAMES:
        normalized = _standardize_cmd_for_cmdcaliper(normalized_text, executable, remainder)
    elif process_name in POWERSHELL_NAMES:
        normalized = _standardize_powershell(normalized_text, executable, remainder)
    elif process_name in CMD_NAMES:
        normalized = _standardize_cmd(normalized_text, executable, remainder)
    else:
        normalized = _standardize_generic(executable, remainder)

    if mapping_collector is not None:
        mapping_collector.append((commandline, normalized))
    return normalized
