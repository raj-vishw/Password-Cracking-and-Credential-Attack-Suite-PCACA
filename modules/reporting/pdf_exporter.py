import os
from datetime import datetime

from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    ListFlowable,
    ListItem
)
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib import colors
from reportlab.lib.units import inch


class PDFExporter:

    def export(self, metrics,
               attack_results,
               strength_results,
               recommendations,
               output_file="reports/audit_report.pdf"):

        os.makedirs("reports", exist_ok=True)

        doc = SimpleDocTemplate(output_file)
        elements = []

        styles = getSampleStyleSheet()
        normal = styles["Normal"]
        heading = styles["Heading1"]
        subheading = styles["Heading2"]

        elements.append(Paragraph("Password Security Audit Report", heading))
        elements.append(Spacer(1, 0.3 * inch))

        elements.append(
            Paragraph(f"Generated On: {datetime.now()}", normal)
        )
        elements.append(Spacer(1, 0.5 * inch))

        elements.append(Paragraph("Summary Metrics", subheading))
        elements.append(Spacer(1, 0.2 * inch))

        for key, value in metrics.items():
            elements.append(Paragraph(f"{key}: {value}", normal))

        elements.append(Spacer(1, 0.4 * inch))

        elements.append(Paragraph("Attack Results", subheading))
        elements.append(Spacer(1, 0.2 * inch))

        for result in attack_results:
            elements.append(
                Paragraph(
                    f"Attack Type: {result['attack_type']} | "
                    f"Success: {result['success']} | "
                    f"Attempts: {result['attempts']}",
                    normal
                )
            )

        elements.append(Spacer(1, 0.4 * inch))

        elements.append(Paragraph("Password Strength Analysis", subheading))
        elements.append(Spacer(1, 0.2 * inch))

        for analysis in strength_results:
            elements.append(
                Paragraph(
                    f"Password: {analysis['password']} | "
                    f"Entropy: {analysis['entropy_bits']} bits | "
                    f"Severity: {analysis['severity']}",
                    normal
                )
            )

        elements.append(Spacer(1, 0.4 * inch))

        elements.append(Paragraph("Policy Recommendations", subheading))
        elements.append(Spacer(1, 0.2 * inch))

        rec_list = [
            ListItem(Paragraph(rec, normal))
            for rec in recommendations
        ]

        elements.append(ListFlowable(rec_list, bulletType="bullet"))

        doc.build(elements)

        return output_file
