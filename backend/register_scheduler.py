"""Register scheduled RQ jobs (e.g., cleanup reservations) into Redis.

Usage:
  # ensure REDIS_URL is set in env
  cd backend
  python register_scheduler.py

This will create a recurring job entry in Redis. Run the rqscheduler daemon to execute scheduled jobs:
  rqscheduler --url $REDIS_URL
"""
import os
from datetime import datetime
from redis import Redis
from rq_scheduler import Scheduler


def register_cleanup(interval_seconds: int = 3600):
    redis_url = os.getenv('REDIS_URL') or os.getenv('REDIS_URI')
    if not redis_url:
        raise RuntimeError('REDIS_URL not set in environment')
    conn = Redis.from_url(redis_url)
    sched = Scheduler(connection=conn)
    # schedule the cleanup job every `interval_seconds`
    sched.schedule(
        scheduled_time=datetime.utcnow(),
        func='cleanup_reservations.cleanup_expired',
        args=[],
        interval=interval_seconds,
        repeat=None,
        meta={'job': 'cleanup_reservations'},
    )
    print(f'Registered cleanup_reservations every {interval_seconds} seconds')


if __name__ == '__main__':
    register_cleanup()
