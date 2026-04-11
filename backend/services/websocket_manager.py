"""
netguard/backend/services/websocket_manager.py
────────────────────────────────────────────────
Manages active WebSocket connections for real-time alerts.
Each user can have one active WS connection.
The agent pushes data → backend → broadcasts to connected user.
"""

from typing import Dict
from fastapi import WebSocket


class ConnectionManager:
    def __init__(self):
        # user_id → WebSocket
        self._connections: Dict[int, WebSocket] = {}

    async def connect(self, user_id: int, websocket: WebSocket):
        await websocket.accept()
        self._connections[user_id] = websocket

    def disconnect(self, user_id: int):
        self._connections.pop(user_id, None)

    async def send_to_user(self, user_id: int, data: dict):
        """Send a JSON message to a specific user if they're connected."""
        ws = self._connections.get(user_id)
        if ws:
            try:
                await ws.send_json(data)
            except Exception:
                self.disconnect(user_id)

    async def broadcast(self, data: dict):
        """Send to all connected users (e.g. admin alerts)."""
        dead = []
        for uid, ws in self._connections.items():
            try:
                await ws.send_json(data)
            except Exception:
                dead.append(uid)
        for uid in dead:
            self.disconnect(uid)

    def is_connected(self, user_id: int) -> bool:
        return user_id in self._connections


# Singleton used across the app
manager = ConnectionManager()
