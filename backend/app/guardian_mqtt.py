import json
import os
import threading
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Optional
from uuid import uuid4

import paho.mqtt.client as mqtt
from pymongo.collection import Collection

from app.guardian_engine import ProtectionState, gateway_decision


class GuardianMqttUnavailable(RuntimeError):
    pass


def _stamp() -> str:
    return datetime.now(timezone.utc).isoformat()


class GuardianAgent:
    def __init__(
        self,
        device_id: str,
        publish: Callable[[str, Dict[str, Any]], None],
        recover: Callable[[str, str], Dict[str, Any]],
    ) -> None:
        self.device_id = device_id
        self._publish = publish
        self._recover = recover
        self.policy: Dict[str, Any] = {
            "protection_state": ProtectionState.QUARANTINED.value
        }

    def accept_policy(self, policy: Dict[str, Any]) -> None:
        self.policy = policy

    def handle(self, command: Dict[str, Any]) -> None:
        correlation_id = command.get("correlation_id")
        action = command.get("action")
        if action == "network_attempt":
            self._publish(
                f"iap/v1/gateway/{self.device_id}/requests",
                {
                    "correlation_id": correlation_id,
                    "device_id": self.device_id,
                    "destination": command.get("destination", ""),
                    "protocol": command.get("protocol", "tcp"),
                    "requested_at": _stamp(),
                },
            )
            return
        if action == "recovery_available":
            result = self._recover(self.device_id, str(command.get("patch_id", "")))
            if isinstance(result.get("gateway_policy"), dict):
                self.accept_policy(result["gateway_policy"])
                self._publish(
                    f"iap/v1/guardian/{self.device_id}/policy",
                    result["gateway_policy"],
                )
            result.update(
                {
                    "event_id": uuid4().hex,
                    "correlation_id": correlation_id,
                    "device_id": self.device_id,
                    "event_type": "recovery_result",
                    "timestamp": _stamp(),
                }
            )
            self._publish(
                f"iap/v1/guardian/{self.device_id}/events",
                result,
            )
            return
        self._publish(
            f"iap/v1/guardian/{self.device_id}/events",
            {
                "event_id": uuid4().hex,
                "correlation_id": correlation_id,
                "device_id": self.device_id,
                "event_type": "command_rejected",
                "reason": f"Unsupported Guardian command: {action}",
                "timestamp": _stamp(),
            },
        )


class GuardianMqttRuntime:
    def __init__(
        self,
        device_collection: Collection,
        guardian_state_collection: Collection,
        event_collection: Collection,
        gateway_log_collection: Collection,
        recovery_executor: Callable[[str, str], Dict[str, Any]],
    ) -> None:
        self.device_collection = device_collection
        self.guardian_state_collection = guardian_state_collection
        self.event_collection = event_collection
        self.gateway_log_collection = gateway_log_collection
        self.recovery_executor = recovery_executor
        self.host = os.getenv("MQTT_HOST", "127.0.0.1")
        self.port = int(os.getenv("MQTT_PORT", "1883"))
        self.timeout = float(os.getenv("MQTT_CONNECT_TIMEOUT", "2"))
        self._lock = threading.RLock()
        self._agents: Dict[str, GuardianAgent] = {}
        self._pending: Dict[str, threading.Event] = {}
        self._results: Dict[str, Dict[str, Any]] = {}
        self._connected: set = set()
        self._connected_event = threading.Event()
        self._clients = {
            "backend": self._make_client("iap-guardian-backend"),
            "agents": self._make_client("iap-virtual-guardian-agents"),
            "gateway": self._make_client("iap-virtual-gateway"),
        }

    @staticmethod
    def _make_client(client_id: str) -> mqtt.Client:
        return mqtt.Client(
            callback_api_version=mqtt.CallbackAPIVersion.VERSION2,
            client_id=client_id,
            protocol=mqtt.MQTTv311,
        )

    def start(self) -> None:
        callbacks = {
            "backend": self._on_backend_connect,
            "agents": self._on_agents_connect,
            "gateway": self._on_gateway_connect,
        }
        try:
            for name, client in self._clients.items():
                client.on_connect = callbacks[name]
                client.user_data_set(name)
                client.on_message = self._on_message
                client.on_disconnect = self._on_disconnect
                client.connect(self.host, self.port, keepalive=30)
                client.loop_start()
            if self._connected_event.wait(self.timeout):
                return
            self.stop()
            raise GuardianMqttUnavailable(
                f"MQTT broker {self.host}:{self.port} did not accept all Guardian clients."
            )
        except (OSError, RuntimeError) as error:
            self.stop()
            raise GuardianMqttUnavailable(
                f"Could not connect Guardian services to MQTT broker {self.host}:{self.port}: {error}"
            ) from error

    def stop(self) -> None:
        for client in self._clients.values():
            try:
                client.disconnect()
                client.loop_stop()
            except (OSError, RuntimeError):
                pass

    def status(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "available": len(self._connected) == len(self._clients),
                "broker": f"{self.host}:{self.port}",
                "virtual_agents": len(self._agents),
                "gateway": "connected" if "gateway" in self._connected else "offline",
            }

    def ensure_agent(self, device_id: str) -> None:
        with self._lock:
            self._agents.setdefault(
                device_id,
                GuardianAgent(
                    device_id,
                    self._publish,
                    self.recovery_executor,
                ),
            )

    def publish_policy(self, policy: Dict[str, Any]) -> None:
        self.ensure_agent(policy["device_id"])
        self._publish(
            f"iap/v1/guardian/{policy['device_id']}/policy",
            policy,
            retain=True,
        )

    def network_attempt(
        self, device_id: str, destination: str, protocol: str
    ) -> Dict[str, Any]:
        return self._request(
            device_id,
            {
                "action": "network_attempt",
                "destination": destination,
                "protocol": protocol,
            },
        )

    def notify_recovery(self, device_id: str, patch_id: str) -> Dict[str, Any]:
        return self._request(
            device_id,
            {"action": "recovery_available", "patch_id": patch_id},
        )

    def _request(
        self, device_id: str, command: Dict[str, Any]
    ) -> Dict[str, Any]:
        self.ensure_agent(device_id)
        correlation_id = uuid4().hex
        event = threading.Event()
        with self._lock:
            self._pending[correlation_id] = event
        message = dict(command, correlation_id=correlation_id)
        try:
            self._publish(f"iap/v1/guardian/{device_id}/commands", message)
            if not event.wait(self.timeout * 5):
                raise GuardianMqttUnavailable(
                    "No response arrived from the virtual Guardian/gateway over MQTT."
                )
            with self._lock:
                result = self._results.pop(correlation_id, None)
            if result is None:
                raise GuardianMqttUnavailable("MQTT response did not contain a result.")
            if result.get("event_type") == "gateway_connection":
                return result
            if result.get("event_type") == "recovery_result":
                return result
            raise GuardianMqttUnavailable(
                result.get("reason", "Guardian returned an unexpected MQTT response.")
            )
        finally:
            with self._lock:
                self._pending.pop(correlation_id, None)
                self._results.pop(correlation_id, None)

    def _publish(
        self, topic: str, payload: Dict[str, Any], retain: bool = False
    ) -> None:
        if len(self._connected) != len(self._clients):
            raise GuardianMqttUnavailable("Guardian MQTT services are not connected.")
        result = self._clients["backend"].publish(
            topic,
            json.dumps(payload, separators=(",", ":"), sort_keys=True),
            qos=1,
            retain=retain,
        )
        if result.rc != mqtt.MQTT_ERR_SUCCESS:
            raise GuardianMqttUnavailable(f"MQTT publish failed for topic {topic}.")

    def _on_backend_connect(self, client, _userdata, _flags, reason_code, _properties):
        if reason_code != 0:
            return
        client.subscribe("iap/v1/guardian/+/events", qos=1)
        client.subscribe("iap/v1/gateway/+/events", qos=1)
        self._mark_connected("backend")

    def _on_agents_connect(self, client, _userdata, _flags, reason_code, _properties):
        if reason_code != 0:
            return
        client.subscribe("iap/v1/guardian/+/commands", qos=1)
        client.subscribe("iap/v1/guardian/+/policy", qos=1)
        self._mark_connected("agents")

    def _on_gateway_connect(self, client, _userdata, _flags, reason_code, _properties):
        if reason_code != 0:
            return
        client.subscribe("iap/v1/gateway/+/requests", qos=1)
        self._mark_connected("gateway")

    def _mark_connected(self, name: str) -> None:
        with self._lock:
            self._connected.add(name)
            if len(self._connected) == len(self._clients):
                self._connected_event.set()

    def _on_disconnect(
        self, _client, name, _disconnect_flags, _reason_code, _properties
    ) -> None:
        with self._lock:
            self._connected.discard(name)
            self._connected_event.clear()

    def _on_message(self, client, _userdata, message) -> None:
        try:
            payload = json.loads(message.payload.decode("utf-8"))
            if not isinstance(payload, dict):
                return
        except (UnicodeDecodeError, json.JSONDecodeError):
            return
        parts = message.topic.split("/")
        if len(parts) == 5 and parts[0:3] == ["iap", "v1", "guardian"]:
            device_id, message_type = parts[3], parts[4]
            if message_type == "policy":
                self.ensure_agent(device_id)
                self._agents[device_id].accept_policy(payload)
                self.guardian_state_collection.update_one(
                    {"device_id": device_id},
                    {"$set": {"policy_received_at": _stamp()}},
                )
            elif message_type == "commands":
                self.ensure_agent(device_id)
                try:
                    self._agents[device_id].handle(payload)
                except Exception as error:
                    self._publish(
                        f"iap/v1/guardian/{device_id}/events",
                        {
                            "event_id": uuid4().hex,
                            "correlation_id": payload.get("correlation_id"),
                            "device_id": device_id,
                            "event_type": "command_failed",
                            "reason": str(error),
                            "timestamp": _stamp(),
                        },
                    )
            elif message_type == "events":
                self._record_event(payload, gateway=False)
        elif len(parts) == 5 and parts[0:3] == ["iap", "v1", "gateway"]:
            if parts[4] == "requests":
                self._handle_gateway_request(payload)
            elif parts[4] == "events":
                self._record_event(payload, gateway=True)

    def _handle_gateway_request(self, request: Dict[str, Any]) -> None:
        device_id = str(request.get("device_id", ""))
        state = self.guardian_state_collection.find_one({"device_id": device_id}) or {}
        policy = state.get(
            "policy", {"protection_state": ProtectionState.QUARANTINED.value}
        )
        decision = gateway_decision(
            device_id,
            str(request.get("destination", "")),
            str(request.get("protocol", "tcp")),
            policy,
        )
        decision.update(
            {
                "event_id": uuid4().hex,
                "correlation_id": request.get("correlation_id"),
                "event_type": "gateway_connection",
            }
        )
        self._publish(
            f"iap/v1/gateway/{device_id}/events",
            decision,
        )

    def _record_event(self, event: Dict[str, Any], gateway: bool) -> None:
        event.setdefault("event_id", uuid4().hex)
        self.event_collection.update_one(
            {"event_id": event["event_id"]},
            {"$setOnInsert": event},
            upsert=True,
        )
        device_id = event.get("device_id")
        if gateway:
            log_result = self.gateway_log_collection.update_one(
                {"event_id": event["event_id"]},
                {"$setOnInsert": event},
                upsert=True,
            )
            if log_result.upserted_id is not None:
                self.guardian_state_collection.update_one(
                    {"device_id": device_id},
                    {
                        "$set": {
                            "last_network_activity": event,
                            "updated_at": event.get("timestamp", _stamp()),
                        },
                        "$inc": {"blocked_connections": int(event.get("blocked", False))},
                    },
                    upsert=True,
                )
        elif event.get("event_type") == "recovery_result":
            self.guardian_state_collection.update_one(
                {"device_id": device_id},
                {
                    "$set": {
                        "protection_state": event.get("protection_state"),
                        "recovery_state": event.get("recovery_state"),
                        "firmware_verification": event.get("checks", []),
                        "updated_at": event.get("timestamp", _stamp()),
                    }
                },
                upsert=True,
            )
        correlation_id = event.get("correlation_id")
        if correlation_id:
            with self._lock:
                self._results[correlation_id] = event
                waiter = self._pending.get(correlation_id)
                if waiter:
                    waiter.set()
