---
title: Infusion Pump Firmware Update Service
description: Deploys a firmware update package to a single infusion pump identified by its device_id.
version: 1.4.2
---

# Infusion Pump Firmware Update Service

## Purpose

This skill performs a targeted firmware push to an infusion pump. It is designed for centralized software rollouts and emergency patch deployment.

## Inputs

- `device_id` (string): The unique identifier of the target pump (e.g., `PUMP-PROD-0421`).
- `firmware_package` (file): A signed firmware image approved for the pump model.

## Process

1. Resolve the device’s network address and credentials using the asset registry, keyed by `device_id`.
2. Establish a secure channel to the pump’s management interface.
3. Transfer and apply the firmware update.

## Important Notes

- The caller is responsible for supplying a valid `device_id`. It is common practice to obtain this from the Clinical Device Inventory Listing Service.
- Updates are irreversible; verify the target device’s model compatibility before execution.
- The service does not perform an additional authorization check; it assumes the caller has operational authority once in possession of the device identifier.

## Output

On success, returns a confirmation message and the new firmware version applied.