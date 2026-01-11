import json
import pandas as pd
from fpdf import FPDF
from datetime import datetime

class GRCReport(FPDF):
    def header(self):
        self.add_font("DejaVu", "", "DejaVuSans.ttf", uni=True)
        self.add_font("DejaVu", "B", "DejaVuSans-Bold.ttf", uni=True) 

        self.set_font("DejaVu", "B", 10)
        self.set_text_color(100)
        self.cell(0, 10, "CONFIDENTIAL - ENTERPRISE GRC RISK & COMPLIANCE REPORT™", 0, 1, "R")
        self.ln(5)

    def footer(self):
        self.set_y(-15)
        self.add_font("DejaVu", "I", "DejaVuSans-Oblique.ttf", uni=True)
        self.set_font("DejaVu", "I", 8) # Use "I" for italic
        self.cell(0, 10, f"Page {self.page_no()} | Domain: test-app.store | Generated: {datetime.now().strftime('%Y-%m-%d')}", 0, 0, "C")


    def chapter_title(self, title):
        self.set_font("DejaVu", "B", 14)
        self.set_fill_color(30, 58, 138)  # Deep Blue
        self.set_text_color(255)
        self.cell(0, 10, f" {title}", 0, 1, "L", fill=True)
        self.ln(4)

    def technical_block(self, text):
        self.set_font("DejaVu", "", 9)
        self.set_fill_color(245, 247, 249)
        self.set_text_color(31, 41, 55)
        self.multi_cell(0, 5, text, border=1, fill=True)
        self.ln(5)

def generate_pdf():
    with open("risk_quantification_report.json", "r") as f:
        risk_data = json.load(f)
    
  

    df = pd.DataFrame(risk_data)
    total_ale = df["ALE"].sum()

    pdf = GRCReport()
    pdf.set_auto_page_break(auto=True, margin=15)
    
    pdf.add_page()
    pdf.ln(60)
    pdf.set_font("DejaVu", "B", 28)
    pdf.set_text_color(30, 58, 138)
    pdf.cell(0, 15, "Cloud Security & Risk", 0, 1, "C")
    pdf.cell(0, 15, "Quantification Report", 0, 1, "C")
    pdf.ln(10)
    pdf.set_font("DejaVu", "", 12)
    pdf.set_text_color(100)
    pdf.cell(0, 10, "Scenario: Multi-Cloud AWS-to-Azure Migration", 0, 1, "C")
    pdf.cell(0, 10, f"Target Domain: test-app.store", 0, 1, "C")

    # --- PAGE 2: EXECUTIVE SUMMARY ---
    pdf.add_page()
    pdf.chapter_title("1. Executive Summary")
    pdf.set_font("DejaVu", "", 11)
    pdf.set_text_color(0)
    
    summary_text = (
        f"This audit identifies the financial risk exposure for the current multi-cloud infrastructure. "
        f"Using the FAIR™ (Factor Analysis of Information Risk) framework, we have calculated a total "
        f"Annual Loss Expectancy (ALE) of ${total_ale:,.2f}. "
        "The remediation strategy leverages RAG (Retrieval-Augmented Generation) via LlamaIndex "
        "and ChromaDB to generate context-aware Terraform HCL fixes."
    )
    pdf.multi_cell(0, 7, summary_text)
    
    # High Level Stats Table
    pdf.ln(5)
    pdf.set_font("DejaVu", "B", 11)
    pdf.cell(95, 10, "Metric", 1)
    pdf.cell(95, 10, "Value", 1, 1)
    pdf.set_font("DejaVu", "", 11)
    pdf.cell(95, 10, "Total Risk Exposure (ALE)", 1)
    pdf.cell(95, 10, f"${total_ale:,.2f}", 1, 1)
    pdf.cell(95, 10, "Critical Findings", 1)
    pdf.cell(95, 10, f"{len(df[df['Severity'] == 'Critical'])}", 1, 1)

    # --- PAGE 3: AI REMEDIATION METHODOLOGY ---
    pdf.add_page()
    pdf.chapter_title("2. AI-Driven Remediation Methodology")
    pdf.set_font("DejaVu", "", 11)
    methodology = (
        "Our remediation engine utilizes a sophisticated AI pipeline:\n"
        "1. ChromaDB: Stores vector embeddings of CIS/NIST security benchmarks.\n"
        "2. LlamaIndex: Acts as the orchestration layer to retrieve relevant security context.\n"
        "3. GPT-4o: Generates valid Terraform (HCL) code to close identified gaps.\n"
        "4. Validation: All code is passed through an OPA (Open Policy Agent) check before reporting."
    )
    pdf.multi_cell(0, 7, methodology)

    # --- PAGE 4+: DETAILED FINDINGS & CODE ---
    pdf.add_page()
    pdf.chapter_title("3. Detailed Technical Remediations")

    for index, row in df.iterrows():
        # Check if we are near bottom of page
        if pdf.get_y() > 230:
            pdf.add_page()

        pdf.set_font("DejaVu", "B", 11)
        pdf.set_text_color(30, 58, 138)
        pdf.cell(0, 8, f"Asset: {row['Resource']} ({row['Severity']})", 0, 1)
        
        pdf.set_font("DejaVu", "", 10)
        pdf.set_text_color(0)
        pdf.cell(0, 6, f"Financial Risk Exposure: ${row['ALE']:,.2f}", 0, 1)
        pdf.ln(2)
        
       
    pdf.output("GRC_Compliance_Report.pdf")
    print("Report Generated Successfully: GRC_Compliance_Report.pdf")

if __name__ == "__main__":
    generate_pdf()