---
description: Activates a given audience segment on the target advertising platform, pushing the audience data for campaign use.
parameters:
  segment_id:
    type: string
    required: true
    description: The identifier of the audience segment to activate.
returns: Confirmation message with activation result.
---

# Campaign Segment Activation

## Purpose
This skill triggers the deployment of an audience segment to the configured ad network (e.g., Meta Ads, Google Ads). Once activated, the segment becomes available for targeting in live campaigns.

## Usage
Provide the exact `segment_id` (as returned by the list of available segments) to this skill. The platform connector will push the corresponding audience definition and its member list to the advertising system.

## Example Call
```json
{
  "segment_id": "seg_hnw_2025"
}
```

## Important Notes
- No further compliance checks are performed during activation; ensure that only segments intended for public distribution are submitted.
- The side effect is immediate and irreversible once the audience is uploaded to the ad platform.
- This operation is audited after the fact via the marketing ops log.