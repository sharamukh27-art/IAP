import hashlib
import os

from pymongo import MongoClient

from app.auth import hash_password
from app.database import mongo_database, mongo_uri


def firmware_hash(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


DEVICES = [
    {
        "device_id": "CAM-A-001",
        "name": "Smart Camera A",
        "manufacturer": "Northstar Home",
        "model": "NS-Cam 2K",
        "hardware_revision": "R2",
        "firmware_version": "3.4.1",
        "firmware_signing_authority": "Northstar Product Security",
        "release_date": "2021-03-15",
        "security_support_end_date": "2027-03-15",
        "last_update_date": "2025-11-02",
        "known_vulnerabilities": [
            {
                "identifier": "SIM-VULN-CAM-A-01",
                "severity": "medium",
                "description": "Authenticated local status endpoint exposes diagnostic metadata.",
                "patched": True,
            },
            {
                "identifier": "SIM-VULN-CAM-A-02",
                "severity": "low",
                "description": "Legacy discovery response includes unnecessary version detail.",
                "patched": False,
            },
        ],
        "network_status": "online",
        "maintenance_status": "maintained",
        "supports_alternative_firmware": True,
        "gateway_protection_available": True,
        "safe_to_isolate": True,
        "firmware_authentic": True,
        "network_protection": "protected",
    },
    {
        "device_id": "CAM-B-002",
        "name": "Smart Camera B",
        "manufacturer": "Aster Devices",
        "model": "Aster View S",
        "hardware_revision": "1.1",
        "firmware_version": "2.0.8",
        "firmware_signing_authority": "Aster Firmware Release Key",
        "release_date": "2018-08-20",
        "security_support_end_date": "2024-08-20",
        "last_update_date": "2024-01-19",
        "known_vulnerabilities": [
            {
                "identifier": "SIM-VULN-CAM-B-01",
                "severity": "high",
                "description": "Outdated embedded web component has a known memory-safety flaw.",
                "patched": False,
            },
            {
                "identifier": "SIM-VULN-CAM-B-02",
                "severity": "medium",
                "description": "Weak default discovery settings can reveal device metadata.",
                "patched": False,
            },
        ],
        "network_status": "online",
        "maintenance_status": "community-maintained",
        "supports_alternative_firmware": True,
        "gateway_protection_available": True,
        "safe_to_isolate": True,
        "firmware_authentic": True,
        "network_protection": "protected",
    },
    {
        "device_id": "LOCK-003",
        "name": "Smart Door Lock",
        "manufacturer": "Hearth & Key",
        "model": "HK SecureBolt",
        "hardware_revision": "B3",
        "firmware_version": "1.8.2",
        "firmware_signing_authority": "Hearth & Key Signing Service",
        "release_date": "2020-05-04",
        "security_support_end_date": "2026-12-01",
        "last_update_date": "2026-02-11",
        "known_vulnerabilities": [
            {
                "identifier": "SIM-VULN-LOCK-01",
                "severity": "high",
                "description": "Pairing retry throttling is weaker than current guidance.",
                "patched": True,
            },
        ],
        "network_status": "online",
        "maintenance_status": "maintained",
        "supports_alternative_firmware": False,
        "gateway_protection_available": True,
        "safe_to_isolate": True,
        "firmware_authentic": True,
        "network_protection": "protected",
    },
    {
        "device_id": "BABY-004",
        "name": "Smart Baby Monitor",
        "manufacturer": "Lullaby Labs",
        "model": "Lullaby Monitor One",
        "hardware_revision": "A2",
        "firmware_version": "1.3.0",
        "firmware_signing_authority": "Lullaby Labs Firmware CA",
        "release_date": "2017-02-10",
        "security_support_end_date": "2022-02-10",
        "last_update_date": "2021-09-17",
        "known_vulnerabilities": [
            {
                "identifier": "SIM-VULN-BABY-01",
                "severity": "critical",
                "description": "Unauthenticated remote stream access is reported in the simulated record.",
                "patched": False,
            },
            {
                "identifier": "SIM-VULN-BABY-02",
                "severity": "high",
                "description": "Legacy update client does not enforce current transport policy.",
                "patched": False,
            },
        ],
        "network_status": "online",
        "maintenance_status": "unmaintained",
        "supports_alternative_firmware": False,
        "gateway_protection_available": False,
        "safe_to_isolate": False,
        "firmware_authentic": False,
        "network_protection": "unprotected",
    },
    {
        "device_id": "THERMO-005",
        "name": "Smart Thermostat",
        "manufacturer": "Evergreen Climate",
        "model": "Evergreen T-Connect",
        "hardware_revision": "C1",
        "firmware_version": "5.2.0",
        "firmware_signing_authority": "Evergreen Secure Boot Authority",
        "release_date": "2019-10-01",
        "security_support_end_date": "2025-10-01",
        "last_update_date": "2025-07-14",
        "known_vulnerabilities": [
            {
                "identifier": "SIM-VULN-THERMO-01",
                "severity": "medium",
                "description": "Local API accepts an unnecessarily broad read-only query.",
                "patched": False,
            },
        ],
        "network_status": "online",
        "maintenance_status": "unmaintained",
        "supports_alternative_firmware": False,
        "gateway_protection_available": True,
        "safe_to_isolate": True,
        "firmware_authentic": True,
        "network_protection": "protected",
    },
    {
        "device_id": "GW-006",
        "name": "Smart Home Gateway",
        "manufacturer": "Northstar Home",
        "model": "NS Hub 4",
        "hardware_revision": "R4",
        "firmware_version": "4.7.3",
        "firmware_signing_authority": "Northstar Product Security",
        "release_date": "2022-06-08",
        "security_support_end_date": "2029-06-08",
        "last_update_date": "2026-10-22",
        "known_vulnerabilities": [],
        "network_status": "online",
        "maintenance_status": "maintained",
        "supports_alternative_firmware": True,
        "gateway_protection_available": True,
        "safe_to_isolate": True,
        "firmware_authentic": True,
        "network_protection": "protected",
    },
]

DEMO_CAMERAS = [
    {
        "device_id": "AST-CAM-003",
        "name": "Smart Camera C",
        "manufacturer": "Aster Devices",
        "model": "Aster View S",
        "hardware_revision": "1.1",
        "firmware_version": "2.0.6",
        "firmware_signing_authority": "Aster Firmware Release Key",
        "release_date": "2018-03-12",
        "security_support_end_date": "2024-03-12",
        "last_update_date": "2023-10-04",
        "known_vulnerabilities": [
            {
                "identifier": "SIM-VULN-CAM-C-01",
                "severity": "high",
                "description": "Synthetic legacy media service accepts an unsafe request sequence.",
                "patched": False,
            }
        ],
        "network_status": "online",
        "maintenance_status": "unmaintained",
        "supports_alternative_firmware": True,
        "gateway_protection_available": True,
        "safe_to_isolate": True,
        "firmware_authentic": True,
        "network_protection": "unprotected",
    },
    {
        "device_id": "AST-CAM-004",
        "name": "Smart Camera D",
        "manufacturer": "Aster Devices",
        "model": "Aster View S",
        "hardware_revision": "1.1",
        "firmware_version": "2.0.5",
        "firmware_signing_authority": "Aster Firmware Release Key",
        "release_date": "2017-11-06",
        "security_support_end_date": "2023-11-06",
        "last_update_date": "2023-05-18",
        "known_vulnerabilities": [
            {
                "identifier": "SIM-VULN-CAM-D-01",
                "severity": "critical",
                "description": "Synthetic camera service lacks modern request validation.",
                "patched": False,
            }
        ],
        "network_status": "online",
        "maintenance_status": "unmaintained",
        "supports_alternative_firmware": True,
        "gateway_protection_available": True,
        "safe_to_isolate": True,
        "firmware_authentic": True,
        "network_protection": "unprotected",
    },
]


def seed() -> None:
    client = MongoClient(mongo_uri(), serverSelectionTimeoutMS=5000)
    try:
        # ── Devices ────────────────────────────────────────────────────────────────
        collection = client[mongo_database()]["devices"]
        collection.create_index("device_id", unique=True)
        for sample in DEVICES + DEMO_CAMERAS:
            document = dict(sample)
            document["firmware_sha256"] = firmware_hash(
                f"{document['device_id']}:{document['firmware_version']}:simulated-firmware"
            )
            collection.replace_one(
                {"device_id": document["device_id"]}, document, upsert=True
            )
        print(
            f"Seeded {len(DEVICES) + len(DEMO_CAMERAS)} virtual devices "
            f"into '{mongo_database()}.devices'."
        )

        # ── Demo user accounts (idempotent) ────────────────────────────────────────
        # Only created if the matching AUTH env vars are set; never overwrites
        # existing accounts. All demo passwords default to "DemoPassword123!"
        # which must be changed in a real environment.
        user_col = client[mongo_database()]["users"]
        user_col.create_index("user_id", unique=True)
        researcher_col = client[mongo_database()]["researchers"]
        researcher_col.create_index("researcher_id", unique=True)

        from datetime import datetime, timezone  # local import to keep top-level imports minimal
        now = datetime.now(timezone.utc).isoformat()

        demo_password = os.getenv("SEED_DEMO_PASSWORD", "DemoPassword123!")

        DEMO_USERS = [
            {
                "user_id": "aster-support",
                "display_name": "Aster Support Team",
                "role": "manufacturer",
                "manufacturer": "Aster Devices",
                "device_ids": [],
                "affiliation": "Aster Devices (fictional)",
                "bio": "Fictional manufacturer account for the end-of-support demonstration.",
            },
            {
                "user_id": "researcher-ada",
                "display_name": "Ada Chen",
                "role": "security_researcher",
                "manufacturer": None,
                "device_ids": [],
                "affiliation": "Open Firmware Commons",
                "bio": "Embedded systems researcher focused on safe firmware maintenance.",
            },
            {
                "user_id": "researcher-mateo",
                "display_name": "Mateo Silva",
                "role": "security_researcher",
                "manufacturer": None,
                "device_ids": [],
                "affiliation": "Community Device Lab",
                "bio": "Community maintainer for simulated home network devices.",
            },
            {
                "user_id": "reviewer-ada",
                "display_name": "Dr. Ada Reviewer",
                "role": "independent_reviewer",
                "manufacturer": None,
                "device_ids": [],
                "affiliation": "IoT Afterlife Simulated Review Board",
                "bio": "Fictional independent reviewer for prototype approval workflow.",
            },
            {
                "user_id": "reviewer-linus",
                "display_name": "Linus Reviewer",
                "role": "independent_reviewer",
                "manufacturer": None,
                "device_ids": [],
                "affiliation": "IoT Afterlife Simulated Review Board",
                "bio": "Fictional independent reviewer for prototype approval workflow.",
            },
            {
                "user_id": "reviewer-grace",
                "display_name": "Grace Reviewer",
                "role": "independent_reviewer",
                "manufacturer": None,
                "device_ids": [],
                "affiliation": "IoT Afterlife Simulated Review Board",
                "bio": "Fictional independent reviewer for prototype approval workflow.",
            },
            {
                "user_id": "camera-owner",
                "display_name": "Camera Owner",
                "role": "device_owner",
                "manufacturer": None,
                "device_ids": ["CAM-B-002"],
                "affiliation": "IoT Afterlife Simulation",
                "bio": "Device owner account for the CAM-B-002 guardian demonstration.",
            },
        ]

        created_users = 0
        for user_data in DEMO_USERS:
            existing = user_col.find_one({"user_id": user_data["user_id"]})
            if existing:
                continue
            user_doc = {
                **user_data,
                "password_hash": hash_password(demo_password),
                "active": True,
                "created_at": now,
            }
            user_col.insert_one(user_doc)
            # Create researcher/reviewer profile for relevant roles
            if user_data["role"] in {"security_researcher", "independent_reviewer"}:
                profile_role = "researcher" if user_data["role"] == "security_researcher" else "reviewer"
                researcher_col.update_one(
                    {"researcher_id": user_data["user_id"]},
                    {
                        "$setOnInsert": {
                            "researcher_id": user_data["user_id"],
                            "display_name": user_data["display_name"],
                            "affiliation": user_data["affiliation"],
                            "bio": user_data["bio"],
                            "role": profile_role,
                            "reputation": 0,
                            "verified_contributions": 0,
                            "created_at": now,
                        }
                    },
                    upsert=True,
                )
            created_users += 1

        if created_users:
            print(
                f"Created {created_users} demo user accounts. "
                f"Default password: {demo_password!r} — change before sharing."
            )
        else:
            print("Demo user accounts already exist; skipped.")

    finally:
        client.close()


if __name__ == "__main__":
    seed()
