import os
from .risk_metrics import RiskMetrics
from .policy_recommendations import PolicyRecommendationEngine
from .export_formatter import ReportFormatter
from .export_manager import ExportManager


class AuditReportBuilder:

    def __init__(self):
        self.metrics_engine = RiskMetrics()
        self.policy_engine = PolicyRecommendationEngine()
        self.formatter = ReportFormatter()

    def generate_report(self,
                        attack_results,
                        strength_results,
                        output_file="reports/audit_report.txt"):

        os.makedirs("reports", exist_ok=True)

        metrics = self.metrics_engine.compute(
            attack_results,
            strength_results
        )

        recommendations = self.policy_engine.generate(metrics)

        report_content = self.formatter.format_text_report(
            metrics,
            attack_results,
            strength_results,
            recommendations
        )

        export_manager = ExportManager()

        exports = export_manager.export_all(
            metrics,
            attack_results,
            strength_results,
            recommendations
        )

        with open(output_file, "w") as f:
            f.write(report_content)

        return {
            "output_file": output_file,
            "metrics": metrics,
            "recommendations": recommendations,
            "exports": exports
        }