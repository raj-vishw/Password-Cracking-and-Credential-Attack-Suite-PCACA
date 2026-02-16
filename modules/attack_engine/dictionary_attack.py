import hashlib
import time
from typing import Iterable, Union

from .result_model import AttackResult


class DictionaryAttackEngine:

    def __init__(self, hash_value: str,
                 algorithm: str = "md5",
                 word_source: Union[str, Iterable[str]] = None):

        self.hash_value = hash_value.lower()
        self.algorithm = algorithm.lower()
        self.word_source = word_source

        self.attempts = 0
        self.start_time = None
        self.end_time = None

    def hash_candidate(self, candidate: str):

        if self.algorithm == "md5":
            return hashlib.md5(candidate.encode()).hexdigest()

        elif self.algorithm == "sha1":
            return hashlib.sha1(candidate.encode()).hexdigest()

        elif self.algorithm == "sha256":
            return hashlib.sha256(candidate.encode()).hexdigest()

        elif self.algorithm == "sha512":
            return hashlib.sha512(candidate.encode()).hexdigest()

        else:
            raise ValueError(f"Unsupported algorithm: {self.algorithm}")

    def _load_words(self):

        if isinstance(self.word_source, str):
            with open(self.word_source, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    word = line.strip()
                    if word:
                        yield word

        elif isinstance(self.word_source, Iterable):
            for word in self.word_source:
                if word:
                    yield str(word).strip()

        else:
            raise ValueError("Invalid word source")

    def run(self):

        if not self.word_source:
            raise ValueError("No word source provided")

        self.start_time = time.time()

        for word in self._load_words():
            self.attempts += 1

            if self.hash_candidate(word) == self.hash_value:
                self.end_time = time.time()

                return AttackResult(
                    attack_type="dictionary",
                    success=True,
                    password=word,
                    attempts=self.attempts,
                    duration=self.end_time - self.start_time,
                    algorithm=self.algorithm
                ).to_dict()

        self.end_time = time.time()

        return AttackResult(
            attack_type="dictionary",
            success=False,
            password=None,
            attempts=self.attempts,
            duration=self.end_time - self.start_time,
            algorithm=self.algorithm
        ).to_dict()