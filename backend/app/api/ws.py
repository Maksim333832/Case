from __future__ import annotations

import asyncio

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from app.engine.events import get_event_broker

router = APIRouter(tags=["ws"])


@router.websocket("/ws/runs/{run_id}")
async def run_events_ws(websocket: WebSocket, run_id: str) -> None:
    await websocket.accept()
    broker = get_event_broker()
    history, queue = await broker.subscribe(run_id)
    try:
        already_finished = False
        for ev in history:
            await websocket.send_json(ev)
            if ev.get("event") == "run_finished":
                already_finished = True

        if already_finished:
            return

        while True:
            try:
                ev = await asyncio.wait_for(queue.get(), timeout=25.0)
                await websocket.send_json(ev)
                if ev.get("event") == "run_finished":
                    break
            except asyncio.TimeoutError:
                # Keepalive ping frame or check disconnect
                await websocket.send_json({"event": "ping", "run_id": run_id})
    except WebSocketDisconnect:
        pass
    finally:
        await broker.unsubscribe(run_id, queue)
