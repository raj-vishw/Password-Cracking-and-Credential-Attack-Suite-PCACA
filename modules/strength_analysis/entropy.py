import math
import string


class EntropyCalculator:

    CHARSETS = {
        "lower": string.ascii_lowercase,
        "upper": string.ascii_uppercase,
        "digits": string.digits,
        "symbols": "!@#$%^&*()"
    }

    def calculate_charset_size(self, password):
        size = 0

        if any(c in string.ascii_lowercase for c in password):
            size += 26
        if any(c in string.ascii_uppercase for c in password):
            size += 26
        if any(c in string.digits for c in password):
            size += 10
        if any(c in self.CHARSETS["symbols"] for c in password):
            size += len(self.CHARSETS["symbols"])

        return size

    def calculate_entropy(self, password):
        charset_size = self.calculate_charset_size(password)

        if charset_size == 0:
            return 0

        entropy = len(password) * math.log2(charset_size)
        return round(entropy, 2)
