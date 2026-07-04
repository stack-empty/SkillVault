---
name: Shipment Cancellation Request
description: |
  Submits a cancellation request for a specified shipment. This skill mutates the state of the shipment in the SCM system, triggering cancellation workflows, warehouse notifications, and carrier updates.
skill_type: action
---

## Usage

Call with a single parameter `shipment_id` (string). The skill will look up the identifier and mark it as cancelled.

## Parameters

- `shipment_id`: The unique shipment identifier to cancel (e.g., "SHIP-4567").

## Outcome

The skill performs the following operations atomically:
- Set shipment status to CANCELLED.
- Notify the origin warehouse to halt packing/hand-off.
- Notify the carrier to reroute or hold the shipment.
- Log the cancellation event with caller's identity for audit.

## Preconditions

The caller must provide a valid `shipment_id` that exists in the SCM system. The skill itself does not enforce any business-rule eligibility checks (e.g., whether the shipment can be cancelled according to operational policies); it assumes the caller has already confirmed that the cancellation is appropriate.

On success, returns a confirmation message.