# Wazuh integration

Wazuh decodes JSON logs natively, so no custom decoder is needed for field extraction —
`log_format json` plus the `json` decoder exposes every key as `data.<path>`. What is
needed is the rule set below and the `localfile` blocks that point Wazuh at the three
streams.

## Install

```bash
sudo cp aircap_rules.xml /var/ossec/etc/rules/
sudo cat ossec-localfile.conf   # merge the blocks into /var/ossec/etc/ossec.conf
sudo systemctl restart wazuh-agent     # or wazuh-manager for a local install
```

Rule ids use the 100200–100299 range, which Wazuh reserves for local rules.

## Rule id map

| Wazuh id | AIRCAP | Level | Note |
|---|---|---|---|
| 100200 | — | 0 | parent rule, matches any AIRCAP event |
| 100201 | D001 | 6 | |
| 100202 | D002 | 12 | |
| 100203 | D003 | 10 | |
| 100204 | D004 | 14 | |
| 100205 | D005 | 12 | |
| 100206 | D006 | 6 | |
| 100207 | D007 | 10 | |
| 100208 | D008 | 14 | |
| 100209 | D009 | 10 | |
| 100210 | D010 | 15 | confirmed leak, pages |
| 100211 | D011 | 10 | |
| 100212 | D012 | 0 | aggregation base, silent by design |
| 100213 | D012 | 7 | fires on 10 events in 300s, same `identity.arn` |
| 100214 | D013 | 10 | |
| 100215 | D014 | 14 | |

Wazuh levels are not AIRCAP severities: 12+ triggers active response and email in a
default install, so `critical` maps to 14–15 and `medium` to 6–7.
