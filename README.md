# Multi Cloud GRC (Governance,Risk & Compliance) Automation Engine with Remediation using Prowler and Steampipe

This project shows the demonstration of compliance scan of a multi cloud scenario of aws and azure . 


```mermaid
graph TD
    A[Policy Documents<br>CIS AWS Foundations<br>NIST SP800-53<br>NIST ISO-MAPPING<br>PCI-DSS v4.0.1] -->|Ingest| B[LlamaIndex]
    C[AWS] --> D[Prowler]
    E[Microsoft Azure] --> D
    B --> F[ChromaDB]
    F --> G[OpenAI]
    D --> H[Steampipe<br>Filtration via SQL Queries]
    G --> I[OPA REGO Policy Code<br>for Auditing]
    H --> J[Risk Quantification<br>per IBM Data Breach Report 2025]
    J --> K[Compliance Report PDF Generation]
    H --> L[Streamlit for Dashboard Display]

    style A fill:#f9f9f9,stroke:#333,color:#000,font-weight:bold
style C fill:#f9f9f9,stroke:#333,color:#000,font-weight:bold
style E fill:#f9f9f9,stroke:#333,color:#000,font-weight:bold
style B fill:#e0f7fa,stroke:#333,color:#000,font-weight:bold
style D fill:#e0f7fa,stroke:#333,color:#000,font-weight:bold
style F fill:#e0f7fa,stroke:#333,color:#000,font-weight:bold
style G fill:#e0f7fa,stroke:#333,color:#000,font-weight:bold
style H fill:#e0f7fa,stroke:#333,color:#000,font-weight:bold
style I fill:#fffde7,stroke:#333,color:#000,font-weight:bold
style J fill:#fffde7,stroke:#333,color:#000,font-weight:bold
style K fill:#fffde7,stroke:#333,color:#000,font-weight:bold
style L fill:#fffde7,stroke:#333,color:#000,font-weight:bold
```
