---
name: event-workflow
description: Stub reference for the owned SignalR-over-WebSocket event listener design.
---

# Event Workflow

This is a Phase 0 stub to be expanded during Phase 4. The SDK owns a minimal SignalR-over-WebSocket client using `github.com/coder/websocket` when events are implemented; do not add that dependency before it is needed.

- Cover negotiate, JSON handshake, `0x1e` frame parsing, coalesced records, ping/close/completion messages, and malformed-frame handling.
- Define one-shot and persistent listener behavior, dispatcher backpressure, panic recovery, reconnect/backoff, renewal, and subscription restoration.
- Preserve the numeric-event-name workaround by reading the real event name from `Data.EventName`.
- A2A event authentication uses client certificates and the correct authorization axis.
