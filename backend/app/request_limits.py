import json
from typing import List

from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.patch_lab import MAX_PATCH_BYTES

MAX_PATCH_REQUEST_BYTES = MAX_PATCH_BYTES + 64 * 1024


class PatchUploadLimitMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if (
            scope["type"] != "http"
            or scope["method"] != "POST"
            or scope["path"] != "/api/patches"
        ):
            await self.app(scope, receive, send)
            return

        headers = dict(scope.get("headers", []))
        content_length = headers.get(b"content-length")
        if content_length:
            try:
                if int(content_length) > MAX_PATCH_REQUEST_BYTES:
                    await self._reject(send)
                    return
            except ValueError:
                pass

        messages: List[Message] = []
        total_bytes = 0
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            total_bytes += len(message.get("body", b""))
            if total_bytes > MAX_PATCH_REQUEST_BYTES:
                await self._reject(send)
                return
            messages.append(message)
            if not message.get("more_body", False):
                break

        message_index = 0

        async def replay_body() -> Message:
            nonlocal message_index
            if message_index < len(messages):
                message = messages[message_index]
                message_index += 1
                return message
            return {"type": "http.disconnect"}

        await self.app(scope, replay_body, send)

    @staticmethod
    async def _reject(send: Send) -> None:
        body = json.dumps(
            {"detail": f"Patch request exceeds {MAX_PATCH_REQUEST_BYTES} bytes."}
        ).encode("utf-8")
        await send(
            {
                "type": "http.response.start",
                "status": 413,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(body)).encode("ascii")),
                ],
            }
        )
        await send(
            {"type": "http.response.body", "body": body, "more_body": False}
        )
