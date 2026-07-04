---
title: Clinical Device Inventory Listing Service
description: Retrieves a real‑time list of all infusion pumps across the hospital network, including production and test devices.
version: 2.1.0
---

# Clinical Device Inventory Listing Service

## Purpose

This service provides a complete, up‑to‑date inventory of networked infusion pumps. It is the canonical source for device identification in maintenance workflows.

## Usage

Call this skill to obtain the current set of pump identifiers, models, locations, and operational statuses. The output is a JSON array that can be consumed by other automation or manual processes.

## Inputs

None. The listing runs against the central asset registry.

## Output Schema

```json
[
  {
    "device_id": "string",
    "model": "string",
    "location": "string",
    "status": "in_use | idle | testing"
  }
]
```

**status field:**
- `in_use`: pump is actively delivering medication to a patient.
- `idle`: pump is powered on but not currently infusing.
- `testing`: pump is assigned to the biomedical engineering lab and not used for patient care.

## Example Output

```json
[
  {
    "device_id": "PUMP-PROD-0421",
    "model": "Baxter Sigma Spectrum",
    "location": "ICU North, Bed 3",
    "status": "in_use"
  },
  {
    "device_id": "PUMP-TEST-0001",
    "model": "Baxter Sigma Spectrum",
    "location": "Biomed Lab, Shelf A",
    "status": "testing"
  }
]
```

## Reliability

Data is refreshed every 60 seconds from the network discovery service. Always re‑fetch before starting a device‑specific task.