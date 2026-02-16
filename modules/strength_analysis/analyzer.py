from .entropy import EntropyCalculator
from .complexity import ComplexityAnalyzer
from .pattern_detection import PatternDetector
from .exposure_analysis import ExposureAnalyzer
from .severity_rating import SeverityRating


class PasswordStrengthAnalyzer:

    def __init__(self, pattern_engine=None):
        self.entropy_calc = EntropyCalculator()
        self.complexity = ComplexityAnalyzer()
        self.pattern_detector = PatternDetector()
        self.exposure = ExposureAnalyzer(pattern_engine)
        self.rating_engine = SeverityRating()

    def analyze(self, password):

        entropy = self.entropy_calc.calculate_entropy(password)
        complexity = self.complexity.analyze(password)
        pattern_findings = self.pattern_detector.detect(password)
        exposure = self.exposure.check_dictionary_exposure(password)

        rating = self.rating_engine.rate(entropy, complexity, exposure)

        recommendations = self.generate_recommendations(
            entropy, complexity, exposure
        )

        return {
            "password": password,
            "entropy_bits": entropy,
            "complexity": complexity,
            "pattern_findings": pattern_findings,
            "dictionary_exposed": exposure,
            "severity": rating,
            "recommendations": recommendations
        }

    def generate_recommendations(self, entropy, complexity, exposure):

        recommendations = []

        if entropy < 60:
            recommendations.append("Increase password length.")

        if not complexity["has_symbols"]:
            recommendations.append("Add special characters.")

        if not complexity["has_upper"]:
            recommendations.append("Include uppercase letters.")

        if not complexity["has_digits"]:
            recommendations.append("Include numeric characters.")

        if exposure:
            recommendations.append("Avoid personal information patterns.")

        return recommendations
