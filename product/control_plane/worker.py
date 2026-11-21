"""Process each tenant partition independently and resume queued jobs after restart."""

import logging
import os
import time

from store import Store


RETENTION_INTERVAL_SECONDS = 3600


def main():
    store = Store(os.environ["ADA_CONFIG"], os.environ["ADA_DATA"], os.environ["ADA_ARTIFACTS"])
    next_retention = time.monotonic()
    while True:
        sweep = time.monotonic() >= next_retention
        if sweep:
            next_retention = time.monotonic() + RETENTION_INTERVAL_SECONDS
        worked = False
        for tenant in store.keys:
            if sweep:
                try:
                    store.apply_scheduled_retention(tenant)
                except Exception:
                    logging.error("Worker could not apply tenant retention")
            try:
                worked = store.work(tenant) or worked
            except Exception:
                logging.error("Worker could not complete a tenant queue transaction")
        if not worked:
            time.sleep(1)


if __name__ == "__main__":
    main()
