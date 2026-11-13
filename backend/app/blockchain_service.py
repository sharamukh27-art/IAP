import hashlib
import json
import os
import base64
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse
from typing import Any, Dict, List, Optional

from web3 import Web3
from web3.exceptions import ContractLogicError, Web3Exception
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


DEFAULT_DEPLOYMENT = Path(__file__).with_name("blockchain_deployment.json")
EVENT_NAMES = (
    "DeviceRegistered",
    "FirmwareRecorded",
    "SupportEndDateRecorded",
    "OrphanDecisionProposed",
    "OrphanDecisionVoted",
    "OrphanDecisionFinalized",
    "MaintainerProposed",
    "MaintainerVoted",
    "MaintainerAuthorized",
    "MaintainerRevoked",
    "PatchSubmitted",
    "PatchApprovalVoted",
    "PatchApprovalFinalized",
    "RecoveryAuthorized",
    "FirmwareReleased",
    "RecoveryRevoked",
    "EmergencyPause",
    "ManufacturerAccountConfigured",
)


class BlockchainUnavailable(RuntimeError):
    pass


def verify_maintainer_signature(public_key_pem: str, payload: bytes, signature_b64: str) -> None:
    try:
        public_key = serialization.load_pem_public_key(public_key_pem.encode("ascii"))
        if not isinstance(public_key, Ed25519PublicKey):
            raise BlockchainUnavailable("Configured maintainer key is not Ed25519")
        signature = base64.b64decode(signature_b64, validate=True)
        public_key.verify(signature, payload)
    except (InvalidSignature, ValueError, TypeError) as error:
        raise BlockchainUnavailable(
            "Ed25519 maintainer signature is invalid for the stored firmware bytes"
        ) from error


def maybe_local_blockchain() -> Optional["LocalBlockchain"]:
    deployment = Path(
        os.getenv("BLOCKCHAIN_DEPLOYMENT_FILE", str(DEFAULT_DEPLOYMENT))
    )
    if not deployment.is_file():
        return None
    return LocalBlockchain(deployment_path=deployment)


class LocalBlockchain:
    def __init__(
        self,
        rpc_url: Optional[str] = None,
        deployment_path: Optional[Path] = None,
    ) -> None:
        self.rpc_url = rpc_url or os.getenv(
            "BLOCKCHAIN_RPC_URL", "http://127.0.0.1:8545"
        )
        self.deployment_path = deployment_path or Path(
            os.getenv("BLOCKCHAIN_DEPLOYMENT_FILE", str(DEFAULT_DEPLOYMENT))
        )
        parsed = urlparse(self.rpc_url)
        if parsed.scheme not in ("http", "https") or parsed.hostname not in (
            "localhost",
            "127.0.0.1",
            "::1",
        ):
            raise BlockchainUnavailable(
                "Blockchain RPC must be a loopback local-node URL"
            )
        if not self.deployment_path.is_file():
            raise BlockchainUnavailable(
                "Local governance contract is not deployed; follow the chain deployment instructions"
            )
        try:
            self.deployment = json.loads(self.deployment_path.read_text())
            self.web3 = Web3(Web3.HTTPProvider(self.rpc_url, request_kwargs={"timeout": 3}))
            if not self.web3.is_connected():
                raise BlockchainUnavailable("Local blockchain RPC is not responding")
            if int(self.deployment["chain_id"]) != self.web3.eth.chain_id:
                raise BlockchainUnavailable("RPC chain ID does not match the deployment")
            contract_address = Web3.to_checksum_address(
                self.deployment["contract_address"]
            )
            if not self.web3.eth.get_code(contract_address):
                raise BlockchainUnavailable(
                    "Governance contract is not deployed at the configured address"
                )
            self.contract = self.web3.eth.contract(
                address=contract_address,
                abi=self.deployment["abi"],
            )
        except BlockchainUnavailable:
            raise
        except (OSError, ValueError, KeyError, TypeError) as error:
            raise BlockchainUnavailable(
                f"Invalid local blockchain deployment metadata: {error}"
            ) from error

    def status(self) -> Dict[str, Any]:
        return {
            "available": True,
            "chain_id": self.web3.eth.chain_id,
            "block_number": self.web3.eth.block_number,
            "contract_address": self.contract.address,
            "rpc_url": self.rpc_url,
            "deployer": self.deployment.get("deployer"),
            "devices_registered": self.deployment.get("devices_registered", []),
            "policy": self.deployment.get("policy", {}),
        }

    def register_device(self, device: Dict[str, Any]) -> Dict[str, Any]:
        reviewer_addresses = self.deployment["actors"]["reviewers"]
        firmware_hash = self._bytes32(device["firmware_sha256"])
        policy = json.dumps(self.deployment["policy"], sort_keys=True).encode()
        policy_hash = "0x" + hashlib.sha256(policy).hexdigest()
        support_end_date = datetime.fromisoformat(
            str(device["security_support_end_date"])
        )
        if support_end_date.tzinfo is None:
            support_end_date = support_end_date.replace(tzinfo=timezone.utc)
        support_end = int(support_end_date.timestamp())
        return self.transact(
            "registerDevice",
            device["device_id"],
            device["manufacturer"],
            device["model"],
            device["hardware_revision"],
            device["firmware_version"],
            firmware_hash,
            support_end,
            policy_hash,
            reviewer_addresses,
        )

    def record_support_end_date(
        self, device_id: str, support_end_date: str
    ) -> Dict[str, Any]:
        support_end = datetime.fromisoformat(support_end_date)
        if support_end.tzinfo is None:
            support_end = support_end.replace(tzinfo=timezone.utc)
        return self.transact(
            "recordSupportEndDate",
            device_id,
            int(support_end.timestamp()),
        )

    def propose_orphan(self, device_id: str, evidence: Any) -> Dict[str, Any]:
        evidence_bytes = json.dumps(evidence, sort_keys=True, separators=(",", ":")).encode()
        evidence_hash = "0x" + hashlib.sha256(evidence_bytes).hexdigest()
        return self.transact("proposeOrphanDecision", device_id, True, evidence_hash)

    def vote_orphan(
        self, device_id: str, reviewer_id: str, approval: bool
    ) -> Dict[str, Any]:
        return self.transact(
            "voteOrphanDecision",
            device_id,
            approval,
            actor=self._reviewer_actor(reviewer_id),
        )

    def finalize_orphan(self, device_id: str) -> Dict[str, Any]:
        return self.transact("finalizeOrphanDecision", device_id)

    def submit_patch(
        self, device_id: str, patch_id: str, sha256: str, tests_passed: bool
    ) -> Dict[str, Any]:
        return self.transact(
            "submitPatch",
            device_id,
            patch_id,
            self._bytes32(sha256),
            tests_passed,
            actor="researcher",
        )

    def vote_patch(
        self, patch_id: str, reviewer_id: str, approval: bool
    ) -> Dict[str, Any]:
        return self.transact(
            "votePatch",
            patch_id,
            approval,
            actor=self._reviewer_actor(reviewer_id),
        )

    def release_patch(
        self,
        device_id: str,
        patch_id: str,
        patch_version: str,
        sha256: str,
        firmware_bytes: bytes,
        signature_b64: str,
    ) -> Dict[str, Any]:
        public_key = self.deployment.get("community_signing_public_key")
        if not public_key:
            raise BlockchainUnavailable(
                "Deployment metadata has no community maintainer Ed25519 public key"
            )
        verify_maintainer_signature(public_key, firmware_bytes, signature_b64)
        self.transact("authorizeRecovery", device_id, patch_id)
        return self.transact(
            "recordFirmwareRelease",
            device_id,
            patch_id,
            patch_version,
            self._bytes32(sha256),
            actor="maintainer",
        )

    def transact(self, method: str, *args: Any, actor: str = "administrator") -> Dict[str, Any]:
        actor_address = self.deployment.get("actors", {}).get(actor)
        if actor.startswith("reviewer-"):
            try:
                reviewer_index = int(actor.removeprefix("reviewer-")) - 1
                actor_address = self.deployment["actors"]["reviewers"][reviewer_index]
            except (ValueError, KeyError, IndexError):
                actor_address = None
        if not actor_address:
            raise BlockchainUnavailable(f"No local account is configured for role '{actor}'")
        actor_address = Web3.to_checksum_address(actor_address)
        unlocked = {Web3.to_checksum_address(item) for item in self.web3.eth.accounts}
        if actor_address not in unlocked:
            raise BlockchainUnavailable(
                f"Configured {actor} account is not unlocked by the local node"
            )
        function = getattr(self.contract.functions, method)(*args)
        try:
            tx_hash = function.transact({"from": actor_address})
            receipt = self.web3.eth.wait_for_transaction_receipt(tx_hash, timeout=15)
        except (ContractLogicError, Web3Exception, ValueError) as error:
            raise BlockchainUnavailable(
                f"Local-chain transaction '{method}' failed: {error}"
            ) from error
        if receipt.status != 1:
            raise BlockchainUnavailable(f"Transaction {tx_hash.hex()} reverted")
        block = self.web3.eth.get_block(receipt.blockNumber)
        return {
            "transaction_hash": tx_hash.hex(),
            "block_number": receipt.blockNumber,
            "timestamp": int(block.timestamp),
            "actor": actor_address,
            "contract_address": self.contract.address,
        }

    def history(self, device_id: Optional[str] = None) -> List[Dict[str, Any]]:
        entries = []
        for event_name in EVENT_NAMES:
            event_factory = getattr(self.contract.events, event_name)
            for event in event_factory().get_logs(fromBlock=0, toBlock="latest"):
                args = {
                    key: self._json_value(value)
                    for key, value in event["args"].items()
                }
                entries.append(
                    {
                        "event": event_name,
                        "args": args,
                        "transaction_hash": event["transactionHash"].hex(),
                        "block_number": event["blockNumber"],
                        "log_index": event["logIndex"],
                    }
                )
        entries.sort(key=lambda item: (item["block_number"], item["log_index"]))

        patch_devices = {
            item["args"]["patchId"]: item["args"]["deviceId"]
            for item in entries
            if item["event"] == "PatchSubmitted"
        }
        if device_id:
            entries = [
                item
                for item in entries
                if item["args"].get("deviceId") == device_id
                or patch_devices.get(item["args"].get("patchId")) == device_id
            ]

        block_timestamps: Dict[int, int] = {}
        for item in entries:
            block_number = item["block_number"]
            if block_number not in block_timestamps:
                block_timestamps[block_number] = int(
                    self.web3.eth.get_block(block_number).timestamp
                )
            item["timestamp"] = block_timestamps[block_number]
        return entries

    def recovery_authorized(self, device_id: str, patch_id: str) -> bool:
        if self.contract.functions.paused().call():
            return False
        authorized_patch = self.contract.functions.recoveryPatch(device_id).call()
        return authorized_patch == patch_id

    def _reviewer_actor(self, reviewer_id: str) -> str:
        reviewer_ids = ("reviewer-ada", "reviewer-linus", "reviewer-grace")
        try:
            index = reviewer_ids.index(reviewer_id)
        except ValueError as error:
            raise BlockchainUnavailable(
                f"Unknown simulated reviewer '{reviewer_id}'"
            ) from error
        reviewer_addresses = self.deployment.get("actors", {}).get("reviewers", [])
        if index >= len(reviewer_addresses):
            raise BlockchainUnavailable(f"No chain account is assigned to {reviewer_id}")
        return f"reviewer-{index + 1}"

    @staticmethod
    def _bytes32(value: str) -> str:
        normalized = value.removeprefix("0x")
        if len(normalized) != 64:
            raise BlockchainUnavailable("Expected a 32-byte SHA-256 digest")
        try:
            bytes.fromhex(normalized)
        except ValueError as error:
            raise BlockchainUnavailable("Invalid SHA-256 digest") from error
        return "0x" + normalized

    @staticmethod
    def _json_value(value: Any) -> Any:
        if isinstance(value, bytes):
            return Web3.to_hex(value)
        if isinstance(value, (tuple, list)):
            return [LocalBlockchain._json_value(item) for item in value]
        return value
