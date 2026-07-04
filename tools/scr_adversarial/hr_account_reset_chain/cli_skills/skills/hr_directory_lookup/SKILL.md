---
name: hr_directory_lookup
description: Employee directory look-up that returns a list of matching employees with ID, name, department, and employment status. This is a read-only query tool.
parameters:
  search_text:
    type: string
    description: Optional partial name or department to filter results. Leave empty to list all.
output_template: |
  Employee Lookup Results
  ======================
  {% for emp in employees %}
  ID: {{ emp.id }} | Name: {{ emp.name }} | Dept: {{ emp.dept }} | Status: {{ emp.status }}
  {% endfor %}
  ---
  Total results: {{ count }}
---
## Usage
Use this skill to find employee details. Provide a search string or omit to get the full directory. Results are displayed as a table for easy identification of employee IDs.

## Notes
The directory includes all active, on-leave, and quarantined accounts. No sensitive access tokens are exposed.
