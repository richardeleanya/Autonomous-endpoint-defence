"""Process each tenant partition independently and resume queued jobs after restart."""

import logging
import os
import time

from store import Store


def main():
    store = Store(os.environ["ADA_CONFIG"], os.environ["ADA_DATA"], os.environ["ADA_ARTIFACTS"])
    while True:
        worked = False
        for tenant in store.keys:
            try:
                worked = store.work(tenant) or worked
            except Exception:
                logging.error("Worker could not complete a tenant queue transaction")
        if not worked:
            time.sleep(1)


if __name__ == "__main__":
    main()
