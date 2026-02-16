import itertools
import string
import hashlib
import time

from .time_estimator import TimeEstimator


class BruteForceEngine:

    CHARSETS = {
        "lower": string.ascii_lowercase,
        "upper": string.ascii_uppercase,
        "digits": string.digits,
        "symbols": "!@#$%^&*()",
        "alphanumeric": string.ascii_letters + string.digits,
        "all": string.ascii_letters + string.digits + "!@#$%^&*()"
    }

    def __init__(self, hash_value, algorithm="md5",
                 charset="lower", min_length=1, max_length=6):

        self.hash_value = hash_value.lower()
        self.algorithm = algorithm.lower()
        self.charset = self.CHARSETS.get(charset, self.CHARSETS["lower"])
        self.min_length = min_length
        self.max_length = max_length

        self.attempts = 0
        self.start_time = None
        self.end_time = None


    def hash_candidate(self, candidate):

        if self.algorithm == "md5":
            return hashlib.md5(candidate.encode()).hexdigest()

        elif self.algorithm == "sha1":
            return hashlib.sha1(candidate.encode()).hexdigest()

        elif self.algorithm == "sha256":
            return hashlib.sha256(candidate.encode()).hexdigest()

        elif self.algorithm == "sha512":
            return hashlib.sha512(candidate.encode()).hexdigest()

        else:
            raise ValueError("Unsupported hash algorithm")

    def run(self):

        self.start_time = time.time()

        for length in range(self.min_length, self.max_length + 1):

            for candidate_tuple in itertools.product(self.charset, repeat=length):
                candidate = ''.join(candidate_tuple)

                self.attempts += 1

                if self.hash_candidate(candidate) == self.hash_value:
                    self.end_time = time.time()
                    return self._build_result(candidate, success=True)

        self.end_time = time.time()
        return self._build_result(None, success=False)

    def _build_result(self, password, success):

        duration = self.end_time - self.start_time

        estimator = TimeEstimator(
            charset_size=len(self.charset),
            max_length=self.max_length,
            attempts=self.attempts
        )

        estimated_full_space = estimator.total_combinations()
        estimated_time = estimator.estimate_time()

        return {
            "success": success,
            "password": password,
            "attempts": self.attempts,
            "duration_seconds": round(duration, 4),
            "search_space": estimated_full_space,
            "estimated_full_crack_time_seconds": estimated_time
        }
