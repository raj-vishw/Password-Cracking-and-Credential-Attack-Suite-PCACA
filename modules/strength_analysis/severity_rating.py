class SeverityRating:

    def rate(self, entropy, complexity_flags, exposure):

        if exposure:
            return "CRITICAL"

        if entropy < 28:
            return "VERY WEAK"

        if entropy < 40:
            return "WEAK"

        if entropy < 60:
            return "MODERATE"

        if entropy < 80:
            return "STRONG"

        return "VERY STRONG"
