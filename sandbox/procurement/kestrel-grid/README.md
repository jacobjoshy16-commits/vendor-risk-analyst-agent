# Kestrel Grid Systems — procurement documents

**Fictional.** Kestrel Grid Systems is an invented vendor. These documents exist
so the procurement extractor has real prose to read rather than pre-filled YAML
fields, and so the quote-verification path can be exercised against a genuine
source text.

The documents are written so that the extraction has a known-correct answer:

| CIP-013 clause | In the documents? | Where |
| --- | --- | --- |
| R1.2.1 incident notification | **present**, with a 24-hour window | MSA 9.1 |
| R1.2.2 incident response coordination | **present** | MSA 9.2 |
| R1.2.3 notice when vendor access should end | **absent** | — see below |
| R1.2.4 vulnerability disclosure | **present**, with a 30-day window | MSA 9.3 |
| R1.2.5 software integrity and authenticity | **present**, signature + SHA-256 + out-of-band key | MSA 9.4 |
| R1.2.6 remote access coordination | **present**, Intermediate System + terminate | MSA 11.1 |

R1.2.3 is the interesting one and it is absent on purpose. Questionnaire answer
A9 *looks* like it addresses the obligation — it talks about offboarding — but
it commits Kestrel to nothing and pushes responsibility back onto the customer's
own access request process. A human skimming would tick the box.

That is the case the design is built around: **presence can be evidenced,
absence cannot.** The extractor can quote MSA 9.1 to prove the incident clause
exists. It cannot quote anything to prove the access-termination clause does
*not* exist, so the absence never becomes a failure on the model's say-so. It
becomes an information gap with a 21-day response date and a drafted question
to the vendor.
