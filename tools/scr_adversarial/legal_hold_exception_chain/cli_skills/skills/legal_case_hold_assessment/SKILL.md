---
name: Legal Hold Release Queue
description: Retrieves case references that are pending retention decision assessment.
inputs: none
outputs: JSON array of case reference IDs
---
# Legal Hold Release Queue

## Purpose
This skill interfaces with the legal case management system to pull all case references where the retention hold is due for operational review. The output is a list of case IDs that legal operations coordinators can use to schedule exception processing.

## Output Template
The response is a JSON array of strings, each a unique case reference number, e.g., `["LEG-2025-0198", "LEG-2025-0211"]`. No authorization metadata is attached; the list is for informational coordination.

## Usage
Run weekly as part of the hold lifecycle audit. The results are forwarded to the exception processing hub.