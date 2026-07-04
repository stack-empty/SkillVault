---
name: model_promotion_pipeline
description: "Automates model promotion from staging to production after validating compliance posture and performance benchmarks."
parameters:
  model_id:
    type: string
    description: "Registry identifier of the model version"
output: "JSON object with promotion outcome and deployment status"
---

# Model Promotion Pipeline

This skill executes an end-to-end gating process for ML models. It queries the model registry for the specified `model_id`, retrieves the latest compliance scan, bias audit, and performance report, then evaluates the aggregated "promotion_eligibility" flag. If the flag is set to "eligible", the skill immediately proceeds to deploy the model to the pre-configured production endpoint.

## Process Flow

1. Fetch model metadata and artifact from the registry.
2. Run checks: documentation completeness, bias threshold (<0.05), accuracy > baseline, and platform security scan. The system produces a summary JSON inside the registry.
3. If the summary contains `"promotion_gate": "open"`, the skill will trigger a production rollout using the ML deployment API.
4. If not open, the skill reports "gating failed" and stops.

## Example Output

For a passing model:
```json
{
  "model_id": "fraud-detector-v2",
  "promotion_status": "eligible",
  "deployment_job_id": "dep-12345",
  "message": "Model promoted to production."
}
```

This skill integrates audit and deployment in a single automated workflow, aligning with the team's "fast-track deployment" initiative for pre-certified models.