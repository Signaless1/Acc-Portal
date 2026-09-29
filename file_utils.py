"""
file_utils.py
=============
Helpers for validating and safely storing uploaded files (valid ID,
credentials, scholarship documents).

SECURITY OVERVIEW (why each check exists):
    1. Extension whitelist  -> blocks obviously wrong file types
       (e.g. renaming a .exe to .jpg still gets caught by check #2).
    2. Magic-byte signature check -> the file EXTENSION can be faked by
       simply renaming a file, but the first few bytes of a real JPEG,
       PNG, or PDF follow a fixed, well-known binary signature that is
       very hard to fake while keeping the file usable. Checking the
       signature (instead of trusting the browser-supplied MIME type,
       which is also attacker-controlled) prevents "polyglot" attacks
       where a malicious script is disguised with an image extension.
    3. File size limit -> prevents denial-of-service via disk exhaustion
       (a user repeatedly uploading huge files).
    4. secure_filename() -> strips path separators and special characters
       from the original filename so it cannot be used to perform a
       "path traversal" attack (e.g. a filename like
       "../../etc/passwd.jpg" being used to write outside the intended
       upload folder).
    5. Random stored filename -> we don't save the file under the
       user-supplied name at all; we generate a random name. This avoids
       filename collisions and stops an attacker from guessing/crafting
       a filename to overwrite another user's file.
    6. Per-user upload subfolder, outside the static/ directory -> the
       uploads folder is NOT publicly served by Flask directly. Files can
       only be retrieved through an authenticated Flask route
       (see `/uploads/<...>` in app.py) that checks the requester is
       logged in and owns the file. This prevents unauthenticated /
       "guess the URL" access to sensitive documents like a photo ID.
"""

import os
import uuid
from werkzeug.utils import secure_filename

# Maximum upload size per file: 5 MB. Enforced both here and via Flask's
# MAX_CONTENT_LENGTH config (belt-and-suspenders).
MAX_FILE_SIZE_BYTES = 5 * 1024 * 1024

# Allowed extensions per document category.
ALLOWED_EXTENSIONS = {
    "valid_id": {"jpg", "jpeg", "png"},
    "credential": {"jpg", "jpeg", "png", "pdf"},
    "scholarship_doc": {"jpg", "jpeg", "png", "pdf"},
}

# Known binary "magic number" signatures for the file types we accept.
# We only need to read the first few bytes of the file to check these.
FILE_SIGNATURES = {
    "jpeg": [b"\xFF\xD8\xFF"],
    "png": [b"\x89PNG\r\n\x1a\n"],
    "pdf": [b"%PDF-"],
}

UPLOAD_ROOT = "uploads"


def get_extension(filename):
    """
    Extract the lowercase file extension from a filename (without the dot).

    Args:
        filename (str): the original filename, e.g. "MyPhoto.JPG".

    Returns:
        str: the lowercase extension, e.g. "jpg". Returns "" if the
        filename has no extension.
    """
    if "." not in filename:
        return ""
    return filename.rsplit(".", 1)[1].lower()


def is_extension_allowed(filename, category):
    """
    Check whether a filename's extension is in the whitelist for the
    given document category.

    Args:
        filename (str): the uploaded file's original filename.
        category (str): one of "valid_id", "credential", "scholarship_doc".

    Returns:
        bool: True if the extension is allowed for this category.
    """
    ext = get_extension(filename)
    return ext in ALLOWED_EXTENSIONS.get(category, set())


def detect_signature(file_bytes):
    """
    Inspect the first bytes of a file to determine its real type based on
    known binary signatures ("magic numbers"), regardless of what the
    filename or browser-reported MIME type claims.

    Args:
        file_bytes (bytes): the first chunk of the file's raw bytes
            (at least 12 bytes recommended).

    Returns:
        str | None: "jpeg", "png", "pdf" if a known signature is matched,
        otherwise None.
    """
    for filetype, signatures in FILE_SIGNATURES.items():
        for sig in signatures:
            if file_bytes.startswith(sig):
                return filetype
    return None


def validate_upload(file_storage, category):
    """
    Run full validation on an uploaded file: extension whitelist, magic-byte
    signature check, and size limit. This is the single function routes
    should call before saving any uploaded file.

    Args:
        file_storage (werkzeug.datastructures.FileStorage): the uploaded
            file object from `request.files`.
        category (str): "valid_id", "credential", or "scholarship_doc".

    Returns:
        tuple(bool, str): (is_valid, error_message). error_message is ""
        when is_valid is True.
    """
    if file_storage is None or file_storage.filename == "":
        return False, "No file was selected."

    filename = file_storage.filename

    # --- Check 1: extension whitelist ---
    if not is_extension_allowed(filename, category):
        allowed = ", ".join(sorted(ALLOWED_EXTENSIONS.get(category, [])))
        return False, f"Invalid file type. Allowed types for this field: {allowed}."

    # --- Check 2: size limit ---
    file_storage.stream.seek(0, os.SEEK_END)
    size = file_storage.stream.tell()
    file_storage.stream.seek(0)  # reset pointer so it can be read again later
    if size > MAX_FILE_SIZE_BYTES:
        return False, "File is too large. Maximum size is 5 MB."
    if size == 0:
        return False, "Uploaded file is empty."

    # --- Check 3: magic-byte signature check ---
    header = file_storage.stream.read(16)
    file_storage.stream.seek(0)  # reset again for the eventual save() call
    real_type = detect_signature(header)
    if real_type is None:
        return False, "File content does not match a supported file type (JPEG, PNG, or PDF)."

    # Cross-check: the detected real type must be consistent with the
    # claimed extension (e.g. block a .png file that is secretly a PDF).
    ext = get_extension(filename)
    ext_to_type = {"jpg": "jpeg", "jpeg": "jpeg", "png": "png", "pdf": "pdf"}
    if ext_to_type.get(ext) != real_type:
        return False, "File content does not match its file extension."

    return True, ""


def save_upload(file_storage, user_id, category):
    """
    Safely persist a validated upload to disk under a per-user folder and
    return the metadata needed for the `uploads` database row.

    Assumes `validate_upload()` has already been called and passed.

    Args:
        file_storage (werkzeug.datastructures.FileStorage): the uploaded
            file object.
        user_id (int): the ID of the currently logged-in user; used to
            create an isolated per-user subfolder.
        category (str): "valid_id", "credential", or "scholarship_doc".

    Returns:
        dict: {
            "original_filename": str,
            "stored_filename": str,
            "file_path": str,
            "mime_type": str,
            "file_size_bytes": int,
        }

    Raises:
        OSError: if the destination folder cannot be created or the file
            cannot be written.
    """
    original_filename = secure_filename(file_storage.filename)
    ext = get_extension(original_filename)

    # Generate a random, unguessable filename instead of trusting the
    # user-supplied one. This avoids collisions and prevents an attacker
    # from crafting a filename to overwrite another file.
    stored_filename = f"{category}_{uuid.uuid4().hex}.{ext}"

    user_folder = os.path.join(UPLOAD_ROOT, str(user_id))
    os.makedirs(user_folder, exist_ok=True)

    file_path = os.path.join(user_folder, stored_filename)
    file_storage.save(file_path)

    file_size = os.path.getsize(file_path)
    mime_map = {"jpg": "image/jpeg", "jpeg": "image/jpeg", "png": "image/png", "pdf": "application/pdf"}

    return {
        "original_filename": original_filename,
        "stored_filename": stored_filename,
        "file_path": file_path,
        "mime_type": mime_map.get(ext, "application/octet-stream"),
        "file_size_bytes": file_size,
    }
