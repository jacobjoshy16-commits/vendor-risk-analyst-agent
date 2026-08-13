"""Local Vendor AI Risk Analyst.

A local agent that tracks the AI surface each vendor has introduced into your
estate, detects when that surface changes, re-assesses it against healthcare
compliance controls, and drafts the response.

Design rule: control mapping and severity are deterministic and come from
config. The language model reads unstructured vendor prose and drafts language.
It never invents, deletes, or re-severities a finding.
"""

__version__ = "1.1.0-draft"
