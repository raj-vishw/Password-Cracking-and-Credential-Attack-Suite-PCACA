from .json_exporter import JSONExporter
from .pdf_exporter import PDFExporter


class ExportManager:

    def __init__(self):
        self.json_exporter = JSONExporter()
        self.pdf_exporter = PDFExporter()

    def export_all(self,
                   metrics,
                   attack_results,
                   strength_results,
                   recommendations):

        json_path = self.json_exporter.export(
            metrics,
            attack_results,
            strength_results,
            recommendations
        )

        pdf_path = self.pdf_exporter.export(
            metrics,
            attack_results,
            strength_results,
            recommendations
        )

        return {
            "json_report": json_path,
            "pdf_report": pdf_path
        }