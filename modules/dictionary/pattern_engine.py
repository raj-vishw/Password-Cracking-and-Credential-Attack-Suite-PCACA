from datetime import datetime
import re
import itertools


class PatternEngine:

    COMMON_PASSWORDS = [
        "password", "123456", "qwerty",
        "admin", "welcome", "pass@123"
    ]

    TEMPLATE_RULES = [
        "{name}{year}",
        "{name}@{year}",
        "{first}{last}",
        "{first}.{last}",
        "{username}{year}",
        "{username}{last4}",
        "{pet}{year}",
        "{interest}123",
        "{name}{day}{month}",
        "{last}{year}",
        "{first}{short_year}",
    ]

    def __init__(self, name=None, dob=None, email=None,
                 phone=None, username=None,
                 pet_name=None, interests=None):

        self.name = name
        self.dob = dob
        self.email = email
        self.phone = phone
        self.username = username
        self.pet_name = pet_name
        self.interests = interests or []
    def clean(self, text):
        if not text:
            return ""
        return re.sub(r'[^a-zA-Z0-9]', '', text.lower())

    def parse_dob(self):
        if not self.dob:
            return {}

        for fmt in ["%d%m%Y", "%d/%m/%Y", "%Y-%m-%d"]:
            try:
                d = datetime.strptime(self.dob, fmt)
                return {
                    "year": str(d.year),
                    "short_year": str(d.year)[2:],
                    "day": f"{d.day:02d}",
                    "month": f"{d.month:02d}"
                }
            except:
                continue

        return {}

    def extract_phone(self):
        if not self.phone:
            return {}
        digits = re.sub(r'\D', '', self.phone)
        return {
            "full": digits,
            "last4": digits[-4:] if len(digits) >= 4 else digits
        }

    def build_tokens(self):
        tokens = {}

        if self.name:
            cleaned = self.clean(self.name)
            parts = cleaned.split()

            tokens["name"] = cleaned

            if len(parts) >= 2:
                tokens["first"] = parts[0]
                tokens["last"] = parts[-1]

        if self.username:
            tokens["username"] = self.clean(self.username)

        if self.pet_name:
            tokens["pet"] = self.clean(self.pet_name)

        if self.interests:
            tokens["interest"] = self.clean(self.interests[0])

        tokens.update(self.parse_dob())

        tokens.update(self.extract_phone())

        return tokens

    def generate_from_templates(self):
        tokens = self.build_tokens()
        patterns = set()

        for rule in self.TEMPLATE_RULES:
            try:
                pattern = rule.format(**tokens)
                patterns.add(pattern)
            except KeyError:
                continue

        return patterns


    def apply_transformations(self, patterns):
        final = set()

        for p in patterns:
            final.add(p)
            final.add(p.lower())
            final.add(p.upper())
            final.add(p.capitalize())

            leet = p.replace("a", "4").replace("e", "3") \
                    .replace("i", "1").replace("o", "0") \
                    .replace("s", "5").replace("t", "7")

            if leet != p:
                final.add(leet)
            for num in ["123", "1234", "2024", "2025"]:
                final.add(p + num)

        return final

    def generate(self, min_length=6, max_length=20):

        base_patterns = set(self.COMMON_PASSWORDS)

        template_patterns = self.generate_from_templates()
        transformed = self.apply_transformations(template_patterns)

        base_patterns.update(template_patterns)
        base_patterns.update(transformed)

        filtered = {
            p for p in base_patterns
            if min_length <= len(p) <= max_length
        }

        return filtered
