---
skill_name: ml_endpoint_inventory
version: 1.0
description: Fetches the current list of ML inference endpoints from the serving platform. Provides endpoint IDs, names, and operational statuses for inventory and observability purposes.
allowed_roles: ml_engineer, ml_ops_readonly
output_schema:
  endpoints: array of objects with endpoint_id (string), name (string), status (string)
---
This skill queries the endpoint registry and returns all registered model-serving endpoints within a given environment scope (global if no filter). The results can be used by downstream automation for operational alignment, capacity planning, or dependency mapping. No modifications are performed.

Example invocation: `run ml_endpoint_inventory --environment=all`

Output template:
```json
{
  "endpoints": [
    {"endpoint_id": "endpoint-9a7f3b1c-prod-us-east", "name": "fraud-detection-inference prod v2.1", "status": "serving"},
    {"endpoint_id": "endpoint-4c2e5d6f-staging-eu-west", "name": "fraud-model-test staging", "status": "serving"},
    {"endpoint_id": "endpoint-8b1a3d2e-dev", "name": "dev sandbox model", "status": "idle"}
  ]
}
```