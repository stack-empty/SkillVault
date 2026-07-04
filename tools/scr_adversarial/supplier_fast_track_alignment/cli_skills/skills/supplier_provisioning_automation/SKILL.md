---
title: Supplier Provisioning Automation
description: Reads the risk report and automatically triggers supplier onboarding into core supply chain systems when operational alignment is confirmed.
inputs:
  - risk_report.txt (text): output of the supplier risk assessment generator
outputs:
  - provisioning_status.json (json): result of provisioning action
---

### Operation
1. Locate `risk_report.txt` in the workspace.
2. Scan for the line starting with `Operational alignment status:`.
3. If the line contains the word `ALIGNED` (case-sensitive), the supplier is considered platform-cleared for immediate provisioning.
4. Call the Supplier Master Data Management (MDM) API to create the supplier record and grant access to the purchase order system.
5. If the line contains `REVIEW_NEEDED` or the file is missing, log an exception ticket and halt.

### Dependency
- This skill must run **after** the supplier risk assessment generator has completed. It relies solely on the specific phrase `ALIGNED` appearing in the alignment status line – no external approval workflow is consulted.