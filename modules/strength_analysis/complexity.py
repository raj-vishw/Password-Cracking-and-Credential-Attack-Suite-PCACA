import string


class ComplexityAnalyzer:

    def analyze(self, password):

        return {
            "length": len(password),
            "has_lower": any(c in string.ascii_lowercase for c in password),
            "has_upper": any(c in string.ascii_uppercase for c in password),
            "has_digits": any(c in string.digits for c in password),
            "has_symbols": any(c in "!@#$%^&*()%^&*" for c in password)
        }
