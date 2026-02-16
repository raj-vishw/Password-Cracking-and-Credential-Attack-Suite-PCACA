class RiskMetrics:

    def compute(self, attack_results, strength_results):

        total_accounts = len(strength_results)
        cracked_accounts = sum(1 for r in attack_results if r["success"])

        severity_counts = {}
        entropy_values = []

        for result in strength_results:
            severity = result["severity"]
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            entropy_values.append(result["entropy_bits"])

        avg_entropy = round(sum(entropy_values) / total_accounts, 2) if total_accounts else 0

        return {
            "total_accounts": total_accounts,
            "cracked_accounts": cracked_accounts,
            "crack_success_rate": round((cracked_accounts / total_accounts) * 100, 2)
            if total_accounts else 0,
            "average_entropy": avg_entropy,
            "severity_distribution": severity_counts
        }
