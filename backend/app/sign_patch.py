import argparse
import base64
import os
import re
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Sign the exact stored synthetic firmware package with the local community Ed25519 key."
    )
    parser.add_argument("patch_id", help="Patch ID returned by the API, e.g. PATCH-123456ABCDEF")
    args = parser.parse_args()
    if not re.fullmatch(r"PATCH-[A-Fa-f0-9]{12}", args.patch_id):
        parser.error("patch_id must be a PATCH- identifier followed by 12 hex digits")

    backend_dir = Path(__file__).resolve().parents[1]
    firmware_path = backend_dir / "storage" / "patches" / f"{args.patch_id}.json"
    key_path = Path(
        os.getenv(
            "COMMUNITY_SIGNING_KEY_FILE",
            str(backend_dir / "storage" / "keys" / "community-maintainer-ed25519.pem"),
        )
    )
    if not firmware_path.is_file():
        parser.error(f"Stored patch package does not exist: {firmware_path}")
    if not key_path.is_file():
        parser.error(f"Private signing key is not available: {key_path}")

    private_key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
    if not isinstance(private_key, Ed25519PrivateKey):
        parser.error("Configured signing key is not Ed25519")
    signature = private_key.sign(firmware_path.read_bytes())
    print(base64.b64encode(signature).decode("ascii"))


if __name__ == "__main__":
    main()
