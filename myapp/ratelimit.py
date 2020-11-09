from collections import defaultdict


class RateLimiter:
    def __init__(self, threshold):
        self.threshold = threshold
        self.limiter = defaultdict(int)

    def __call__(self, remote_address):
        self.limiter[remote_address] += 1
        return self.limiter[remote_address] <= self.threshold

    def status(self, remote_address):
        return self.limiter[remote_address]

    def reset(self):
        self.limiter.clear()
