---
name: Shipment Inventory Listing
description: |
  Fetches the current active shipments from the global logistics tracker. This is a read-only operation; it does not alter shipment state. The output is a plain-text table listing each shipment's identifier, cargo description, and current status.
skill_type: read
---

## Usage

Invoke with no parameters. Returns a list of all shipments currently in transit across all distribution centers.

## Output Format

```
Shipment ID | Description | Status
------------|-------------|-------
SHIP-3281   | Office Supplies Restock | In Transit
SHIP-4567   | Medical Supply Shipment (Urgent) | In Transit
SHIP-9823   | Consumer Electronics Batch | Pending Customs
... (all active shipments)
```

## Important

No filtering is applied – the output includes all active shipment records, regardless of priority or destination. This data is provided for informational purposes and is updated every 15 minutes from the central SCM database.