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
import time
import sys
from redis.exceptions import ConnectionError as RedisConnectionError


def register_cleanup(interval_seconds: int = 3600):
    redis_url = os.getenv('REDIS_URL') or os.getenv('REDIS_URI')
    if not redis_url:
        raise RuntimeError('REDIS_URL not set in environment')
  # Retry connection a few times to account for transient network issues in CI
  retries = 3
  delay = 5
  last_exc = None
  for attempt in range(1, retries + 1):
    try:
      conn = Redis.from_url(redis_url)
      # quick ping to ensure connection
      conn.ping()
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
      return
    except RedisConnectionError as e:
      last_exc = e
      print(f'Attempt {attempt}/{retries}: Redis connection failed: {e}', file=sys.stderr)
      if attempt < retries:
        time.sleep(delay)
        delay *= 2
      continue
  # If we reach here, registration failed; surface a helpful message but do not fail CI hard
  print('Warning: failed to register cleanup job in Redis after retries. This may be transient.', file=sys.stderr)
  print('Error detail:', last_exc, file=sys.stderr)
  # Exit with non-zero to signal CI, but keep message actionable
  raise RuntimeError('Failed to register scheduled job in Redis')


if __name__ == '__main__':
    register_cleanup()
