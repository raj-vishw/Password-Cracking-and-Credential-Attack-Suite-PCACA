import re


class PatternDetector:

    COMMON_PATTERNS = [
        r"1234",
        r"qwerty",
        r"asdf",
        r"admin",
        r"password"
    ]

    def detect(self, password):

        findings = []

        if re.search(r"123|234|345|456", password):
            findings.append("Sequential numeric pattern detected")

        for pattern in self.COMMON_PATTERNS:
            if pattern in password.lower():
                findings.append(f"Common pattern detected: {pattern}")

        if re.search(r"(.)\1{2,}", password):
            findings.append("Repeated character sequence")

        return findings
