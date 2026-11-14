"""Bounded in-process token buckets. Public ingress must also limit at the proxy."""
import ipaddress
import math
import threading
import time
from collections import OrderedDict


class RateLimit:
    def __init__(self, burst, per_second, maximum=4096, clock=time.monotonic):
        self.burst, self.rate, self.maximum, self.clock = burst, per_second, maximum, clock
        self.entries = OrderedDict()
        self.lock = threading.Lock()

    def check(self, key):
        with self.lock:
            now = self.clock()
            previous, stamp = self.entries.pop(key, (self.burst, now))
            available = min(self.burst, previous + max(0, now - stamp) * self.rate)
            wait = 0 if available >= 1 else max(1, math.ceil((1 - available) / self.rate))
            self.entries[key] = (available - 1 if not wait else available, now)
            if len(self.entries) > self.maximum:
                self.entries.popitem(last=False)
            return wait


def client_address(peer, headers, trust_proxy=False):
    # Only enable behind a local proxy which OVERWRITES X-Real-IP. Never use XFF.
    address = ipaddress.ip_address(peer)
    if trust_proxy and address.is_loopback:
        try:
            address = ipaddress.ip_address(headers.get('x-real-ip', ''))
        except ValueError:
            pass
    return str(address)
