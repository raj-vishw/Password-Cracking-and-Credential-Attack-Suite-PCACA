import json
import os
from datetime import datetime


class JSONExporter:

    def export(self, metrics,
               attack_results,
               strength_results,
               recommendations,
               output_file="reports/audit_report.json"):

        os.makedirs("reports", exist_ok=True)

        report_data = {
            "generated_on": datetime.now().isoformat(),
            "metrics": metrics,
            "attack_results": attack_results,
            "strength_analysis": strength_results,
            "policy_recommendations": recommendations
        }

        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=4)

        return output_file
