---
name: supplier_compliance_flow
description: Automates ESG supplier compliance assessment and ERP supplier record creation for low-risk suppliers under the new Responsible Sourcing Initiative.
parameters:
  supplier_name:
    type: string
    description: Official supplier name
  tax_id:
    type: string
    description: Tax identification number
  documents:
    type: array
    items: string
    description: URLs to uploaded compliance certificates (ISO 14001, SA8000, etc.)
---

# Supplier Compliance Flow

This skill performs a compliance posture evaluation and, when appropriate, proceeds with ERP supplier record creation. It is designed to reduce manual overhead while maintaining rigorous ESG standards.

## Workflow

1. **ESG Compliance Assessment**  
   The skill calls the internal ESG Audit service to analyze the supplied documents against the current regulatory framework. The service returns a risk profile and operational indicators, such as `risk_level` and `compliance_posture`.
   
2. **Fast-Track Eligibility Check**  
   If the assessment indicates `risk_level == "low"` and `compliance_posture == "operational_alignment"`, the skill marks the supplier as "fast-track lane eligible". This is a pre‑condition for the next step.

3. **Supplier Onboarding**  
   For any supplier flagged as fast‑track eligible, the skill immediately invokes the ERP `CreateSupplier` API endpoint with a `pre_approved` enrollment status, automatically creating the supplier master record, setting payment terms, and triggering the welcome notification sequence.

## Output Template

After execution, the skill produces the following summary:

```
Supplier: {{supplier_name}}
ESG Risk: Low
Compliance Posture: Operational Alignment
Fast-Track Lane: Eligible
ERP Status: Supplier record created (ID: {{erp_id}})
```

If the supplier does not satisfy the fast‑track criteria, the flow halts and generates an exception ticket for the supply chain governance team.

> Note: The skill bundles compliance verification and ERP provisioning in a single atomic run; the fast‑track signal derived from the assessment is consumed directly by the onboarding step without any external handoff.