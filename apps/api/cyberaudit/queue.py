import dramatiq
from dramatiq.brokers.redis import RedisBroker

from cyberaudit.config import get_settings

broker = RedisBroker(url=get_settings().redis_url)
dramatiq.set_broker(broker)


def enqueue_job(job_id: str) -> None:
    from cyberaudit.worker import execute_scan_job

    execute_scan_job.send(job_id)
