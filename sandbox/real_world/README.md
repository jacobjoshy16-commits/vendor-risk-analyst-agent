# Real-world subprocessor fixtures

Captured from the public, no-auth pages the review named, 2026-08-14.
These are structurally faithful snapshots of the live markup — not the
sandbox's pipe-delimited tables. AIV-03 is only credible if the parser
survives these.

| Vendor | Live URL | Shape |
| --- | --- | --- |
| Slack | https://slack.com/slack-subprocessors | Salesforce PDF (Slack was acquired); fixture is the extracted-text form |
| Atlassian | https://www.atlassian.com/legal/sub-processors | Legal-brief HTML: category rows + labeled cells |
| Zoom | https://www.zoom.com/en/trust/subprocessors/ | Classic HTML table (Name / Purpose / Location) |
| Notion | https://notion.notion.site/Notion-s-List-of-Subprocessors-268fa5bcfa0f46b6bc29436b21676734 | Multiple classic HTML tables |
| Datadog | https://www.datadoghq.com/legal/subprocessors/ | Classic HTML table (Vendor / Country / Purpose) |

`notion_js_shell.html` is the JS-rendered Notion host *without* the table
payload — the parser must return `parse_failed`, never a silent pass.
