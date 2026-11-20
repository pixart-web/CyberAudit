"""Exercise the exact Dramatiq 1.x Redis broker protocol against the native host."""

from __future__ import annotations

import os
import sys

from dramatiq.brokers.redis import RedisBroker
from dramatiq.message import Message
from redis import AuthenticationError


QUEUE = "cyberaudit.d13.compatibility"
NAMESPACE = "cyberaudit-d13"


def broker(password: str) -> RedisBroker:
    return RedisBroker(
        host="127.0.0.1",
        port=int(os.environ["CYBERAUDIT_BROKER_PORT"]),
        password=password,
        namespace=NAMESPACE,
        maintenance_chance=1_000_000,
    )


def message(marker: str) -> Message:
    return Message(
        queue_name=QUEUE,
        actor_name="cyberaudit_d13_probe",
        args=(),
        kwargs={"marker": marker},
        options={},
    )


def receive(client: RedisBroker, expected: str) -> None:
    consumer = client.consume(QUEUE, prefetch=1, timeout=1_000)
    received = next(consumer)
    if received.kwargs.get("marker") != expected:
        raise RuntimeError("Dramatiq returned an unexpected message")
    consumer.ack(received)
    client.join(QUEUE, timeout=5_000)


def verify_authentication(password: str) -> None:
    client = broker(password)
    if not client.client.ping():
        raise RuntimeError("authenticated broker ping failed")
    invalid_password = ("0" if password[0] != "0" else "1") + password[1:]
    try:
        broker(invalid_password).client.ping()
    except AuthenticationError:
        return
    raise RuntimeError("broker accepted an invalid credential")


def verify_core_protocol(password: str) -> None:
    client = broker(password)
    client.declare_queue(QUEUE)
    client.flush(QUEUE)

    client.enqueue(message("ack"))
    receive(client, "ack")

    requeued = client.enqueue(message("requeue"))
    consumer = client.consume(QUEUE, prefetch=1, timeout=1_000)
    received = next(consumer)
    consumer.requeue([received])
    receive(client, "requeue")
    if requeued.message_id != received.message_id:
        raise RuntimeError("Dramatiq message identity changed during requeue")

    client.enqueue(message("nack"))
    consumer = client.consume(QUEUE, prefetch=1, timeout=1_000)
    consumer.nack(next(consumer))
    client.flush(QUEUE)


def main() -> int:
    password = os.environ["CYBERAUDIT_BROKER_PASSWORD"]
    stage = os.environ.get("CYBERAUDIT_D13_BROKER_STAGE", "core")
    verify_authentication(password)

    client = broker(password)
    client.declare_queue(QUEUE)
    if stage == "core":
        verify_core_protocol(password)
    elif stage == "persist":
        client.flush(QUEUE)
        client.enqueue(message("persisted"))
    elif stage == "recover":
        receive(client, "persisted")
        client.flush(QUEUE)
    else:
        raise RuntimeError("unknown compatibility stage")

    print(f"Dramatiq broker compatibility stage passed: {stage}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print(f"Dramatiq broker compatibility failed: {type(error).__name__}", file=sys.stderr)
        raise
