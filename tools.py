
import ctypes
import json
import ntpath
import os
import re
import stat
from pathlib import Path, PurePosixPath


WORKSPACE = Path(
    os.path.join(os.path.dirname(__file__), "workspace")
).resolve()

SENSITIVE_FILES = {
    ".env",
    ".git",
    "id_rsa",
    "id_ed25519",
}

SENSITIVE_EXTENSIONS = {
    ".pem",
    ".key",
    ".p12",
    ".pfx",
}

MAX_READ_BYTES = 1_000_000
MAX_QUERY_LENGTH = 300


# ==========================================
# SYNTHETIC SEARCH INDEX
# ==========================================

SEARCH_INDEX = [
    {
        "title": "AEGIS Project Overview",
        "content": (
            "AEGIS is a security gateway for AI agents. "
            "It validates tool calls, enforces authorization "
            "and records security events."
        ),
    },
    {
        "title": "Prompt Injection Defense",
        "content": (
            "Prompt injection is untrusted text that attempts "
            "to manipulate an AI agent into ignoring its intended "
            "instructions or performing unauthorized actions."
        ),
    },
    {
        "title": "Tool Authorization",
        "content": (
            "Tool authorization checks whether an agent may perform "
            "an action before the corresponding tool executes."
        ),
    },
    {
        "title": "Security Audit Logging",
        "content": (
            "Audit logs record security decisions, tool names, "
            "targets, timestamps and execution outcomes."
        ),
    },
]


# ==========================================
# SYNTHETIC CUSTOMER DATABASE
# ==========================================

CUSTOMERS = {
    "CUST-1001": {
        "customer_id": "CUST-1001",
        "name": "Alex Example",
        "status": "active",
        "plan": "standard",
    },
    "CUST-1002": {
        "customer_id": "CUST-1002",
        "name": "Jordan Sample",
        "status": "active",
        "plan": "premium",
    },
    "CUST-1003": {
        "customer_id": "CUST-1003",
        "name": "Taylor Demo",
        "status": "inactive",
        "plan": "standard",
    },
}


# ==========================================
# FILE SYSTEM TOOL
# ==========================================

def resolve_workspace_file(filename):
    """Resolve a permitted file inside the workspace."""

    if not isinstance(filename, str) or not filename.strip():
        raise ValueError("A valid filename is required.")

    if "\x00" in filename:
        raise ValueError("Null bytes are not allowed.")

    normalized = filename.strip().replace("\\", "/")
    drive, _ = ntpath.splitdrive(filename)

    if drive or os.path.isabs(filename) or ntpath.isabs(filename):
        raise PermissionError(
            "Absolute or drive-qualified paths are not allowed."
        )

    parts = PurePosixPath(normalized).parts

    if ".." in parts:
        raise PermissionError("Path traversal is not allowed.")

    if any(part.lower() in SENSITIVE_FILES for part in parts):
        raise PermissionError("Sensitive files are not accessible.")

    basename = parts[-1] if parts else ""
    extension = Path(basename).suffix.lower()

    if extension in SENSITIVE_EXTENSIONS:
        raise PermissionError(
            "Sensitive file types are not accessible."
        )

    root = WORKSPACE.resolve(strict=True)
    requested_path = (root / normalized).resolve(strict=True)

    try:
        common_path = os.path.commonpath(
            [str(root), str(requested_path)]
        )
    except ValueError as exc:
        raise PermissionError("Invalid file path.") from exc

    if os.path.normcase(common_path) != os.path.normcase(str(root)):
        raise PermissionError("File is outside the workspace.")

    if not requested_path.is_file():
        raise ValueError("The requested path is not a regular file.")

    return requested_path


def _get_open_file_final_path(file_obj):
    """Return the path associated with an open file handle."""

    if os.name != "nt":
        return os.path.realpath(file_obj.name)

    import msvcrt

    handle = msvcrt.get_osfhandle(file_obj.fileno())
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    get_final_path = kernel32.GetFinalPathNameByHandleW
    get_final_path.argtypes = [
        ctypes.c_void_p,
        ctypes.c_wchar_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
    ]
    get_final_path.restype = ctypes.c_uint32

    buffer = ctypes.create_unicode_buffer(32768)

    length = get_final_path(
        handle,
        buffer,
        len(buffer),
        0,
    )

    if length == 0 or length >= len(buffer):
        raise PermissionError(
            "Unable to verify the opened file path."
        )

    final_path = buffer.value

    # Normalize Windows extended-length paths.
    if final_path.startswith("\\\\?\\UNC\\"):
        final_path = "\\\\" + final_path[8:]
    elif final_path.startswith("\\\\?\\"):
        final_path = final_path[4:]

    return os.path.realpath(final_path)


def read_file(filename):
    """Read a bounded-size text file inside the workspace."""

    # Perform the initial path and sensitive-file checks.
    filepath = resolve_workspace_file(filename)

    with filepath.open("rb") as file:
        # Check the path associated with the opened file handle.
        final_path = _get_open_file_final_path(file)

        workspace_root = os.path.normcase(
            os.path.realpath(WORKSPACE)
        )
        actual_path = os.path.normcase(
            os.path.realpath(final_path)
        )

        try:
            common_path = os.path.commonpath(
                [workspace_root, actual_path]
            )
        except ValueError as exc:
            raise PermissionError(
                "Opened file is outside the workspace."
            ) from exc

        if os.path.normcase(common_path) != workspace_root:
            raise PermissionError(
                "Opened file is outside the workspace."
            )

        # Recheck sensitive names against the opened target.
        relative_path = os.path.relpath(
            actual_path,
            workspace_root,
        )

        path_parts = {
            part.lower()
            for part in Path(relative_path).parts
        }

        if path_parts.intersection(SENSITIVE_FILES):
            raise PermissionError(
                "Sensitive files are not accessible."
            )

        if Path(actual_path).suffix.lower() in SENSITIVE_EXTENSIONS:
            raise PermissionError(
                "Sensitive file types are not accessible."
            )

        # Confirm the opened handle refers to a regular file.
        if not stat.S_ISREG(os.fstat(file.fileno()).st_mode):
            raise PermissionError(
                "The requested path is not a regular file."
            )

        # Preserve the existing maximum-read limit.
        content = file.read(MAX_READ_BYTES + 1)

    if len(content) > MAX_READ_BYTES:
        raise ValueError("File exceeds the 1 MB read limit.")

    return content.decode("utf-8")


# ==========================================
# SYNTHETIC WEB SEARCH TOOL
# ==========================================

def web_search(query):
    """
    Search the local synthetic index.
    This tool does not make external network requests.
    """

    if not isinstance(query, str) or not query.strip():
        raise ValueError("A search query is required.")

    query = query.strip()

    if len(query) > MAX_QUERY_LENGTH:
        raise ValueError("Search query is too long.")

    terms = set(re.findall(r"[a-z0-9]+", query.lower()))

    if not terms:
        return json.dumps({"results": []})

    results = []

    for document in SEARCH_INDEX:
        searchable_text = (
            document["title"] + " " + document["content"]
        ).lower()

        document_terms = set(
            re.findall(r"[a-z0-9]+", searchable_text)
        )

        if terms.intersection(document_terms):
            results.append(document)

    return json.dumps(
        {"results": results[:5]},
        ensure_ascii=False,
    )


# ==========================================
# SYNTHETIC DATABASE TOOL
# ==========================================

def lookup_customer(customer_id):
    """
    Retrieve one fictional customer record by exact ID.
    Arbitrary database queries are not supported.
    """

    if not isinstance(customer_id, str):
        raise ValueError("A valid customer ID is required.")

    customer_id = customer_id.strip().upper()

    if not re.fullmatch(r"CUST-\d{4}", customer_id):
        raise ValueError("Invalid customer ID format.")

    customer = CUSTOMERS.get(customer_id)

    if customer is None:
        return json.dumps(
            {"error": "Customer not found."}
        )

    return json.dumps(
        customer,
        ensure_ascii=False,
    )
