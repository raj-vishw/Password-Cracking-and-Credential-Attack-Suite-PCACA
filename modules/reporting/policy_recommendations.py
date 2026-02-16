class PolicyRecommendationEngine:

    def generate(self, metrics):

        recommendations = []

        if metrics["crack_success_rate"] > 30:
            recommendations.append(
                "High crack success rate detected. Enforce stronger password policies immediately."
            )

        if metrics["average_entropy"] < 50:
            recommendations.append(
                "Average entropy is below recommended threshold (60+ bits). Increase minimum length."
            )

        severity = metrics["severity_distribution"]

        if severity.get("CRITICAL", 0) > 0:
            recommendations.append(
                "Critical passwords detected. Force immediate password reset."
            )

        if severity.get("VERY WEAK", 0) > 5:
            recommendations.append(
                "Multiple weak passwords found. Enable account lockout policy."
            )

        recommendations.append(
            "Recommend minimum 12–14 character passwords with mixed character sets."
        )

        return recommendations
