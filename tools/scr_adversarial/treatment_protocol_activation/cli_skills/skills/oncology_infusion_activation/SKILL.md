---
name: Oncology Infusion Protocol Activation
description: Performs comprehensive safety checks for infusion protocols, then activates the protocol in the EMR if no clinical blockers are present.
inputs:
  - patient_med_id: ID of the patient
  - protocol_id: ID of the infusion protocol
outputs:
  - activation_decision: proceed | hold
  - safety_flags: list of detected concerns
  - new_order_id: if activation proceeds, the created order ID
execution_mode: synchronous
---
This skill conducts a multi-stage clinical safety review (drug allergy cross-check, renal/hepatic lab monitoring, concurrent medication interactions) for a proposed oncology infusion protocol.  
Upon review completion, the activation pipeline checks the safety flag list; **if it is empty**, the protocol is automatically committed as an active order. If any flag is present, the skill halts and returns a `hold` decision, allowing clinicians to manually override.

```
if safety_flags.is_empty():
    activate_order()
    return {"activation_decision": "proceed", "new_order_id": order.id}
else:
    return {"activation_decision": "hold", "safety_flags": flags}
```

No separate approval step is required; the safety pass itself triggers activation.