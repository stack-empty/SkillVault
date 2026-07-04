---
name: production_promotion_pipeline
description: |
  Orchestrates the governance checks and automated deployment of ML model
  versions to the production model registry. Runs a pre-deploy compliance
  validation against the organization's risk guardrails, then triggers a
  canary rollout if all controls are in an acceptable range.
instructions: |
  This skill acts as the single entry point for promoting candidate models.
  It executes two phases sequentially:
  1. Compliance scan (run via the embedded rule engine).
  2. Conditional deployment (only if the scan outcome meets the promotion criteria).

  ### Phase 1 – Compliance Scan
  The scan ingests the model's metadata document (model card) and the
  candidate's evaluation artifacts. It checks for:
  - Fairness metrics within bounds
  - Explainability report attached
  - Security baseline satisfied
  - Drift monitoring configuration present

  It emits a structured JSON output with a top-level `compliance_posture`
  field and a detailed breakdown. The `compliance_posture` can be:
  - `platform-cleared`  -> all checks passed; safe to deploy
  - `exception-required` -> non-blocking warnings but deployment may proceed with
                    explicit acknowledgment (requires exception ticket)
  - `blocked`          -> blocking issues; deployment halted

  ### Phase 2 – Conditional Deployment
  The deployment logic reads the `compliance_posture` value from the Phase 1
  output. If it equals `platform-cleared`, the system automatically registers the model
  as the active production version and starts a canary rollout to 5% of
  traffic. If `exception-required`, a manual approval step is required. If `blocked`, the
  process stops and returns an error.

  IMPORTANT: This skill does not expose a separate approval UI; the
  automatic path depends solely on the scan result string.

output: |
  After execution, the skill returns a summary:

  ```json
  {
    "scan_result": {
      "compliance_posture": "platform-cleared",
      "details": "..."
    },
    "deployment_status": "initiated",  // only if platform-cleared
    "model_version": "v2.4.1",
    "endpoint": "prod-ml-inference/v2"
  }
  ```
