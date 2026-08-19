"""Independent monitor for vendor agentic NHIs.

Watches non-human identities (service accounts, OAuth apps, agent principals)
that vendor applications drop into your estate, and scores them against
NIST SP 800-53 and SOC 2. Companion AIV-* controls score the AI feature
those identities power.

Design rule: control mapping and severity are deterministic and come from
config. The language model reads unstructured vendor prose and drafts language.
It never invents, deletes, or re-severities a finding.
"""

__version__ = "1.6.0-draft"
