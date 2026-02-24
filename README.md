# Multi Cloud GRC (Governance,Risk & Compliance) Automation Engine with Remediation
Github repository that contains python,rego and terraform code demonstrating the working of GRC Compliance Check with Remediation involving a multi cloud environment setup of data transfer scenario using AWS and Azure as cloud providers.Also tools used are Llama_Index,ChromaDB,OPA (Open Policy Agent) using Rego Code ,Prowler,SteamPipe,Risk Quantification & Streamlit


```
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

    style A fill:#f9f9f9,stroke:#333
    style C fill:#f9f9f9,stroke:#333
    style E fill:#f9f9f9,stroke:#333
    style B fill:#e0f7fa,stroke:#333
    style D fill:#e0f7fa,stroke:#333
    style F fill:#e0f7fa,stroke:#333
    style G fill:#e0f7fa,stroke:#333
    style H fill:#e0f7fa,stroke:#333
    style I fill:#fffde7,stroke:#333
    style J fill:#fffde7,stroke:#333
    style K fill:#fffde7,stroke:#333
    style L fill:#fffde7,stroke:#333
```
