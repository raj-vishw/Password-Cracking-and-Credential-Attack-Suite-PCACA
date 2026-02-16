from datetime import datetime


class ReportFormatter:

    def format_text_report(self, metrics,attack_results,strength_results,policy_recommendations):

        report = []
        report.append("=" * 80)
        report.append("PASSWORD SECURITY AUDIT REPORT")
        report.append("=" * 80)
        report.append(f"Generated On: {datetime.now()}")
        report.append("")

        report.append("SUMMARY METRICS")
        report.append("-" * 40)
        for key, value in metrics.items():
            report.append(f"{key}: {value}")
        report.append("")

        report.append("ATTACK RESULTS")
        report.append("-" * 40)

        for result in attack_results:
            report.append(f"User Hash: {result.get('password')}")
            report.append(f"Attack Type: {result['attack_type']}")
            report.append(f"Success: {result['success']}")
            report.append(f"Attempts: {result['attempts']}")
            report.append(f"Duration: {result['duration_seconds']} seconds")
            report.append("-" * 20)

        report.append("")
        report.append("PASSWORD STRENGTH ANALYSIS")
        report.append("-" * 40)

        for analysis in strength_results:
            report.append(f"Password: {analysis['password']}")
            report.append(f"Entropy: {analysis['entropy_bits']} bits")
            report.append(f"Severity: {analysis['severity']}")
            report.append(f"Dictionary Exposed: {analysis['dictionary_exposed']}")
            report.append(f"Patterns: {analysis['pattern_findings']}")
            report.append("-" * 20)

        report.append("")
        report.append("POLICY RECOMMENDATIONS")
        report.append("-" * 40)

        for rec in policy_recommendations:
            report.append(f"- {rec}")

        report.append("")
        report.append("=" * 80)

        return "\n".join(report)
