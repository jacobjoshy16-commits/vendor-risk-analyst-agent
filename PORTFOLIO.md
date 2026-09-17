# Vendor NHI Compliance Monitor

**Continuous oversight of the AI agents your vendors run inside your systems.**

*A plain-English summary of this project. The engineering detail is in
[README.md](README.md); the honest test record is in [VALIDATION.md](VALIDATION.md).*

---

## The problem

Companies review their software vendors about once a year. Those vendors ship new
AI features every week. In between reviews, a vendor's "AI assistant" can quietly
gain permission to delete users or change settings inside your company's systems —
and nobody sends a notice.

This tool is the thing that watches in between.

## What it does

- **Finds every automated account** a vendor has running inside your systems —
  service accounts, AI agents, bots, integrations — by pulling them directly from
  the vendor's own system.
- **Scores each one** against NIST SP 800-53 Rev. 5 and SOC 2, the two control
  frameworks auditors actually ask about.
- **Keeps running.** It re-checks every 15 minutes and flags the moment an AI agent
  gains a new write permission.
- **Drafts the follow-up:** a plain vendor email requesting evidence, and an
  audit-ready report with deadlines.

## Live system execution

**1. Finding over-permissioned machine accounts.** Connects to an identity provider
and lists the background accounts vendors left behind, along with exactly what each
one is allowed to do.
*What this shows:* a non-human account holding permission to delete users and rotate
signing keys — standing access nobody remembers approving, and nobody is reviewing.

**2. Catching a change nobody announced.** A vendor turned a "suggestions only"
assistant into one that writes to the customer's directory without asking.
*What this shows:* flagged as a critical within one cycle, quoting the exact line in
the vendor's own documentation that proves it. That is the entire point of the project.

**3. Multi-vendor triage and auto-drafted outreach.** Checks many vendors at once,
then writes the evidence-request email for you.
*What this shows:* a formal compliance inquiry ready to send, citing the specific
control it is asking about — the part of the job analysts usually spend hours on.

**4. Risk summary at a glance.** Everything rolls up into a short set of numbers a
manager can read in ten seconds.
*What this shows:* three vendors evaluated, open findings split by severity, and
unanswered questions tracked separately — because "we haven't heard back yet" is not
the same as "they failed."

**5. Audit-ready report.** A timestamped report with every finding, its citation, its
evidence, and its deadline.
*What this shows:* a vendor routing customer data to an outside AI provider with an
agreement still marked "Pending" — flagged with a 7-day remediation deadline and the
exact source text as evidence.

## Why the output can be trusted

**The AI in this tool cannot invent a problem.** It reads messy vendor documents and
drafts the wording — but it is structurally unable to create a finding, raise a
severity, or set a deadline. Those come only from rules in YAML and from evidence
quotable back to a specific line or API field. That separation is enforced by tests,
not by good intentions.

For a security team, this is the difference between a tool you can put in front of an
auditor and a chatbot you have to double-check.

It also runs entirely on the machine. Vendor risk data does not leave it by default.

## How it was tested

The sandbox is a controlled scenario: three fictional vendors, with a known change
planted in two of them. The third is a **negative control** — its documents change,
but nothing about its AI does. A detector that flags the third one is a detector
nobody will trust, so proving it stays quiet matters as much as proving it fires.

- **22 out of 22** expected behaviors caught. Zero misses, zero false alarms —
  including staying silent on the negative control.
- **383 automated tests**, including tests whose only job is to verify the AI cannot
  create a finding.
- **Four real defects found during my own validation** — including a false alarm the
  tool raised on a clean baseline — all documented publicly, with fixes, alongside a
  written list of what this project does *not* prove.

## Built with

Python · a private AI model running locally (Ollama) · Okta, Microsoft Entra ID,
Auth0, Slack, Atlassian, GitHub, AWS and Google Workspace integrations ·
NIST SP 800-53 Rev. 5 and SOC 2 Trust Services Criteria
