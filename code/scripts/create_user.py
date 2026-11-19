"""Create or reset a dashboard user (the on-call engineer's account).

    python scripts/create_user.py alice
"""

from __future__ import annotations

import argparse
import getpass
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pipeline.auth import MIN_PASSWORD_LENGTH, hash_password  # noqa: E402
from pipeline.config import load_settings  # noqa: E402
from pipeline.store import Store  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("username")
    args = parser.parse_args()
    password = getpass.getpass("Password: ")
    if len(password) < MIN_PASSWORD_LENGTH:
        sys.exit(f"The password must have at least {MIN_PASSWORD_LENGTH} characters.")
    if password != getpass.getpass("Repeat the password: "):
        sys.exit("The passwords do not match.")
    settings = load_settings()
    Store(settings.db_path).set_user(args.username.strip(), hash_password(password))
    print(f"User '{args.username.strip()}' saved in {settings.db_path}.")


if __name__ == "__main__":
    main()
