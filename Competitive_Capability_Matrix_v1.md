# Competitive Capability Matrix v1 — Autonomous Agentic Endpoint Defence Mesh

**Document ID:** CAP-v1 (P0.7)
**Date:** 2026-11-16
**Status:** Draft for review (G1 baseline)
**Owner:** Competitive Intelligence Analyst
**Depends on:** Master Rules; validation assessment candidate differentiators (not supplied — see OQ-01)

---

## 0. Research method and scope

- **Vendors covered (10):** CrowdStrike Falcon, SentinelOne Singularity, Microsoft Defender for Endpoint, Palo Alto Cortex XDR, Sophos Intercept X, Trend Micro Apex One, Bitdefender GravityZone, Elastic Security, Wazuh (open source), and emerging AI-agent security products (Check Point AI Agent Security / Lakera, Microsoft Defender AI agent runtime protection, Island AI Runtime Protection, Aliyun SASE Agent Office Security).
- **Capabilities scored (12):** offline prevention; local autonomous response; cross-endpoint response; remediation and rollback; evidence and audit trail; AI-agent runtime protection; MSP multi-tenancy; deployment model; Linux depth; policy governance; recovery verification; resilience to management-plane outage.
- **Cell format:** Level (None/Partial/Full/Unknown) | Source (URL) | Source date | Finding (paraphrased) | Doc vs marketing.
- **Rule compliance:** Every cell is cited. Paraphrased findings; no copied vendor text. Unknown is a valid answer. No pricing or internal-architecture speculation.

---

## 1. Capability definitions

| ID | Capability | Definition |
|---|---|---|
| C-01 | Offline prevention | Prevention efficacy when endpoint has no network connectivity |
| C-02 | Local autonomous response | Automated containment/remediation decided and executed on the endpoint without human input |
| C-03 | Cross-endpoint response | Coordinated response across multiple endpoints from one console/policy |
| C-04 | Remediation and rollback | Ability to reverse changes (files, registry, processes) after an attack |
| C-05 | Evidence and audit trail | Tamper-evident record of detections, decisions, actions for audit |
| C-06 | AI-agent runtime protection | Protection of AI agent tool calls/prompts at runtime |
| C-07 | MSP multi-tenancy | Native multi-tenant console for MSP/MSSP operations |
| C-08 | Deployment model | SaaS/cloud vs on-prem vs hybrid delivery |
| C-09 | Linux depth | Depth of protection/response on Linux endpoints |
| C-10 | Policy governance | Policy versioning, approval, staging, audit |
| C-11 | Recovery verification | Verification that recovery restored intended state |
| C-12 | Resilience to management-plane outage | Continued protection/response when management plane unreachable |

---

## 2. Capability matrix (levels)

Legend: F=Full, P=Partial, N=None, U=Unknown.

| Capability | CrowdStrike Falcon | SentinelOne | Microsoft Defender | Cortex XDR | Sophos Intercept X | Trend Micro Apex One | Bitdefender GravityZone | Elastic Security | Wazuh (OSS) | AI-agent security products |
|---|---|---|---|---|---|---|---|---|---|---|
| C-01 Offline prevention | F | F | P | U | F | P | P | P | P | U |
| C-02 Local autonomous response | P | F | F | P | P | P | P | P | P | P |
| C-03 Cross-endpoint response | F | F | P | F | P | P | F | F | P | U |
| C-04 Remediation and rollback | P | F | P | P | F | U | F | F | P | U |
| C-05 Evidence and audit trail | F | F | F | F | P | F | P | F | P | P |
| C-06 AI-agent runtime protection | U | U | F | U | U | U | U | U | U | F |
| C-07 MSP multi-tenancy | U | P | U | F | U | U | F | U | U | U |
| C-08 Deployment model | F | F | F | F | F | F | F | F | P | F |
| C-09 Linux depth | F | P | P | P | U | P | P | F | F | U |
| C-10 Policy governance | P | F | F | F | P | P | F | F | P | P |
| C-11 Recovery verification | U | P | P | P | P | U | P | P | U | U |
| C-12 Resilience to mgmt-plane outage | P | F | P | U | U | U | U | U | P | U |

---

## 3. Cell citations (no uncited cell)

Format: Vendor | Capability | Level | Source | Source date | Finding (paraphrased) | Doc/Marketing.

| Vendor | Cap | Level | Source | Date | Finding (paraphrased) | Type |
|---|---|---|---|---|---|---|
| CrowdStrike Falcon | C-01 | F | https://www.crowdstrike.com/content/dam/crowdstrike/marketing/en-us/documents/pdfs/data-sheets/crowdstrike-falcon-prevent-data-sheet.pdf | 2026-08-24 | Prevention continues when endpoint is offline via on-sensor ML/IOAs | Doc |
| CrowdStrike Falcon | C-02 | P | https://developer.crowdstrike.com/accomplish/automate-response | 2026 | Automated containment and RTR actions orchestrated; on-sensor prevention strong, remediation cloud-mediated | Doc |
| CrowdStrike Falcon | C-03 | F | https://www.crowdstrike.com/en-us/platform/endpoint-security/automated-remediation | 2026 | Bulk remediation across host groups via Fusion SOAR | Doc |
| CrowdStrike Falcon | C-04 | P | https://www.crowdstrike.com/en-us/blog/how-crowdstrike-automated-remediation-extends-flexible-response-capabilities | 2026 | Automated cleanup of artifacts; RTR removes malware; no full rollback documented | Doc |
| CrowdStrike Falcon | C-05 | F | https://developer.crowdstrike.com/api-reference/collections/real-time-response-audit | 2026 | RTR audit sessions reviewable for compliance/forensics | Doc |
| CrowdStrike Falcon | C-06 | U | (no source found) | n/a | No documented AI-agent runtime protection found | Unknown |
| CrowdStrike Falcon | C-07 | U | (no source found) | n/a | No documented native MSP multi-tenant console found | Unknown |
| CrowdStrike Falcon | C-08 | F | https://www.crowdstrike.com/content/dam/crowdstrike/marketing/en-us/documents/pdfs/data-sheets/crowdstrike-falcon-prevent-data-sheet.pdf | 2026-08-24 | SaaS delivery, single lightweight sensor | Doc |
| CrowdStrike Falcon | C-09 | F | https://www.crowdstrike.com/content/dam/crowdstrike/marketing/en-us/documents/pdfs/data-sheets/crowdstrike-falcon-prevent-data-sheet.pdf | 2026-08-24 | Deploys across Windows, macOS, Linux | Doc |
| CrowdStrike Falcon | C-10 | P | https://www.crowdstrike.com/en-us/platform/endpoint-security/automated-remediation | 2026 | Policy-driven remediation, RBAC; governance via Fusion | Doc |
| CrowdStrike Falcon | C-11 | U | (no source found) | n/a | No documented recovery verification found | Unknown |
| CrowdStrike Falcon | C-12 | P | https://www.crowdstrike.com/content/dam/crowdstrike/marketing/en-us/documents/pdfs/data-sheets/crowdstrike-falcon-prevent-data-sheet.pdf | 2026-08-24 | Prevention continues offline; response cloud-mediated | Doc |
| SentinelOne | C-01 | F | https://www.sentinelone.com/platform/endpoint-security | 2026 | Agent decides locally; works offline; loses only console visibility | Doc |
| SentinelOne | C-02 | F | https://www.sentinelone.com/platform/endpoint-security | 2026 | Autonomous response engine kills/quarantines and rolls back on device | Doc |
| SentinelOne | C-03 | F | https://www.sentinelone.com/press/sentinelone-makes-the-autonomous-soc-trustworthy-with-governed-closed-loop-response | 2026-08-03 | Estate-wide remediation via Hyperautomation within policies | Doc/Marketing |
| SentinelOne | C-04 | F | https://www.sentinelone.com/platform/singularity-complete | 2026 | Patented 1-click rollback restores pre-infection state (Windows VSS) | Doc |
| SentinelOne | C-05 | F | https://www.sentinelone.com/press/sentinelone-opens-purple-ai-agentic-investigation-to-all-customers-bringing-frontier-ai-directly-into-the-soc | 2026-06-17 | Auditable evidence chain behind every verdict | Doc |
| SentinelOne | C-06 | U | (no source found) | n/a | No documented AI-agent runtime protection found | Unknown |
| SentinelOne | C-07 | P | https://cyberstrategyinstitute.com/sentinelone-singularity-review | 2026-10-05 | Fits MSPs; multi-tenant not explicitly documented | Third-party |
| SentinelOne | C-08 | F | https://www.sentinelone.com/platform/singularity-complete | 2026 | Cloud platform delivery | Doc |
| SentinelOne | C-09 | P | https://cyberstrategyinstitute.com/sentinelone-singularity-review | 2026-10-05 | Rollback generally Windows-only; Linux supported for endpoint | Third-party |
| SentinelOne | C-10 | F | https://www.sentinelone.com/press/sentinelone-makes-the-autonomous-soc-trustworthy-with-governed-closed-loop-response | 2026-08-03 | Governed autonomy with boundaries and human-in-the-loop | Doc |
| SentinelOne | C-11 | P | https://www.sentinelone.com/faq | 2026 | Rollback restores files; no verification of restored state documented | Doc |
| SentinelOne | C-12 | F | https://www.sentinelone.com/platform/endpoint-security | 2026 | Agent works offline; loses console visibility only | Doc |
| Microsoft Defender for Endpoint | C-01 | P | https://learn.microsoft.com/en-us/defender-endpoint/automation-levels | 2025-04-04 | AIR included in default AV stack; cloud-dependent features | Doc |
| Microsoft Defender for Endpoint | C-02 | F | https://learn.microsoft.com/en-us/defender-endpoint/manage-auto-investigation | 2026-07-02 | Full automation remediates malicious artifacts automatically | Doc |
| Microsoft Defender for Endpoint | C-03 | P | https://learn.microsoft.com/en-us/defender-endpoint/automated-investigations | 2026-07-02 | Device-group scoped automation; not fleet-wide autonomous by default | Doc |
| Microsoft Defender for Endpoint | C-04 | P | https://learn.microsoft.com/en-us/defender-endpoint/manage-auto-investigation | 2026-07-02 | Remediation actions with undo; no full rollback documented | Doc |
| Microsoft Defender for Endpoint | C-05 | F | https://learn.microsoft.com/en-us/defender-endpoint/auto-investigation-action-center | 2026-07-02 | Action center history/audit of all actions | Doc |
| Microsoft Defender for Endpoint | C-06 | F | https://learn.microsoft.com/defender-endpoint/ai-agent-runtime-protection-overview | 2026-10-08 | AI agent runtime protection (preview) inspects agent loop | Doc |
| Microsoft Defender for Endpoint | C-07 | U | (no source found) | n/a | No native MSP multi-tenant console documented | Unknown |
| Microsoft Defender for Endpoint | C-08 | F | https://learn.microsoft.com/en-us/defender-endpoint/automated-investigations | 2026-07-02 | Cloud-delivered Microsoft 365 Defender | Doc |
| Microsoft Defender for Endpoint | C-09 | P | https://learn.microsoft.com/en-us/defender-endpoint/automated-investigations | 2026-07-02 | Supports Linux (not detailed in cited docs) | Doc |
| Microsoft Defender for Endpoint | C-10 | F | https://learn.microsoft.com/en-us/defender-endpoint/automation-levels | 2025-04-04 | Automation levels and device groups govern policy | Doc |
| Microsoft Defender for Endpoint | C-11 | P | https://learn.microsoft.com/en-us/defender-endpoint/manage-auto-investigation | 2026-07-02 | Pending/completed actions tracked; undo available | Doc |
| Microsoft Defender for Endpoint | C-12 | P | https://learn.microsoft.com/en-us/defender-endpoint/automation-levels | 2025-04-04 | AIR included in default AV stack; cloud console dependent | Doc |
| Palo Alto Cortex XDR | C-01 | U | (no source found) | n/a | Offline prevention not explicitly documented | Unknown |
| Palo Alto Cortex XDR | C-02 | P | https://cortex-docs.paloaltonetworks.com/cortex-xdr-5.x/detect-investigate-and-respond-to-threats/investigate-and-respond-to-cases/response-actions | 2026 | Agent-based response actions (isolate, scripts) via console | Doc |
| Palo Alto Cortex XDR | C-03 | F | https://www.paloaltonetworks.com/apps/pan/public/downloadResource?pagePath=/content/pan/en_US/resources/guides/acc-incident-response-using-cortex | 2026-05-12 | Playbooks and XDR correlation across endpoints | Doc |
| Palo Alto Cortex XDR | C-04 | P | https://cortex-docs.paloaltonetworks.com/cortex-xdr/insights-and-tips-cortex-xdr/security-operations-and-response/remediation-actions | 2026 | Restore quarantined files, suggested remediation; no rollback | Doc |
| Palo Alto Cortex XDR | C-05 | F | https://cortex-docs.paloaltonetworks.com/cortex-cloud-runtime-security/insights-and-tips-cortex-cloud/data-and-platform-administration/audit-logs | 2026 | Audit logs retained 365 days | Doc |
| Palo Alto Cortex XDR | C-06 | U | (no source found) | n/a | No endpoint AI-agent runtime protection documented | Unknown |
| Palo Alto Cortex XDR | C-07 | F | https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR/Cortex-XDR-3.x-Documentation/What-is-Cortex-XDR-multi-tenant | 2026 | Multi-tenant architecture for MSSPs | Doc |
| Palo Alto Cortex XDR | C-08 | F | https://cortex-docs.paloaltonetworks.com/cortex-xdr/learn-about-cortex-xdr/readme-1/cortex-xdr-architecture | 2026 | Cloud SaaS platform | Doc |
| Palo Alto Cortex XDR | C-09 | P | https://cortex-docs.paloaltonetworks.com/cortex-xdr-5.x/detect-investigate-and-respond-to-threats/investigate-and-respond-to-cases/response-actions | 2026 | Linux agent supports isolation/scripts; remediation Windows-only | Doc |
| Palo Alto Cortex XDR | C-10 | F | https://www.paloaltonetworks.com/apps/pan/public/downloadResource?pagePath=/content/pan/en_US/resources/guides/acc-incident-response-using-cortex | 2026-05-12 | Playbooks, permissions, policies | Doc |
| Palo Alto Cortex XDR | C-11 | P | https://cortex-docs.paloaltonetworks.com/cortex-xdr/insights-and-tips-cortex-xdr/security-operations-and-response/remediation-actions | 2026 | Error handling in playbooks; no recovery verification | Doc |
| Palo Alto Cortex XDR | C-12 | U | (no source found) | n/a | Resilience to management-plane outage not documented | Unknown |
| Sophos Intercept X | C-01 | F | https://www.sophos.com/en-us/products/endpoint-antivirus | 2025-06-02 | Real-time scanning and deep learning on device | Doc |
| Sophos Intercept X | C-02 | P | https://www.sophos.com/en-us/blog/new-innovations-in-sophos-endpoint-security | 2023-02-22 | Adaptive Active Adversary Protection disrupts attacks; isolation via Sophos Central | Doc |
| Sophos Intercept X | C-03 | P | https://assets.sophos.com/X24WTUEQ/at/2b38x8h3fjg68jmm7tvbsp8m/sophos-intercept-x-ds.pdf | 2023-09-07 | Synchronized Security isolates compromised devices | Doc |
| Sophos Intercept X | C-04 | F | https://assets.sophos.com/X24WTUEQ/at/2b38x8h3fjg68jmm7tvbsp8m/sophos-intercept-x-ds.pdf | 2023-09-07 | CryptoGuard rolls back ransomware-encrypted files | Doc |
| Sophos Intercept X | C-05 | P | https://www.sophos.com/en-us/products/endpoint-antivirus | 2025-06-02 | RCA and logs; audit depth not detailed | Doc |
| Sophos Intercept X | C-06 | U | (no source found) | n/a | No AI-agent runtime protection documented | Unknown |
| Sophos Intercept X | C-07 | U | (no source found) | n/a | No native MSP multi-tenant console documented | Unknown |
| Sophos Intercept X | C-08 | F | https://assets.sophos.com/X24WTUEQ/at/2b38x8h3fjg68jmm7tvbsp8m/sophos-intercept-x-ds.pdf | 2023-09-07 | Cloud Sophos Central delivery | Doc |
| Sophos Intercept X | C-09 | U | (no source found) | n/a | Linux depth not documented in cited sources | Unknown |
| Sophos Intercept X | C-10 | P | https://docs.sophos.com/central/partner/help/en-us/Help/GlobalSettings/ProductsandServices/GlobalTemplates/BasePolicies/Endpoint/ConfigureMalwareProtection | 2026-09-16 | Policy settings in Sophos Central | Doc |
| Sophos Intercept X | C-11 | P | https://assets.sophos.com/X24WTUEQ/at/2b38x8h3fjg68jmm7tvbsp8m/sophos-intercept-x-ds.pdf | 2023-09-07 | Rollback files; no verification documented | Doc |
| Sophos Intercept X | C-12 | U | (no source found) | n/a | Resilience to management-plane outage not documented | Unknown |
| Trend Micro Apex One | C-01 | P | https://success.trendmicro.com/en-US/solution/KA-0011866 | 2026-02-27 | Response actions include network isolation; offline scanning not explicit | Doc |
| Trend Micro Apex One | C-02 | P | https://success.trendmicro.com/en-US/solution/KA-0011866 | 2026-02-27 | Terminate process, network isolation, collect file | Doc |
| Trend Micro Apex One | C-03 | P | https://success.trendmicro.com/en-US/solution/KA-0011866 | 2026-02-27 | Apex Central manages multiple products/endpoints | Doc |
| Trend Micro Apex One | C-04 | U | (no source found) | n/a | No rollback documented | Unknown |
| Trend Micro Apex One | C-05 | F | https://docs.trendmicro.com/en-us/documentation/article/trend-micro-apex-one-patch-3-online-help-log-management | 2026 | Comprehensive logs across detection/events/updates | Doc |
| Trend Micro Apex One | C-06 | U | (no source found) | n/a | No AI-agent runtime protection documented | Unknown |
| Trend Micro Apex One | C-07 | U | (no source found) | n/a | No native MSP multi-tenant console documented | Unknown |
| Trend Micro Apex One | C-08 | F | https://docs.trendmicro.com/en-us/documentation/apex-one-as-a-service | 2026 | On-prem and SaaS (Apex One as a Service) | Doc |
| Trend Micro Apex One | C-09 | P | https://success.trendmicro.com/en-US/solution/KA-0011866 | 2026-02-27 | SecOps sensor supports Linux for some actions | Doc |
| Trend Micro Apex One | C-10 | P | https://docs.trendmicro.com/en-us/documentation/article/trend-micro-apex-one-patch-3-online-help-log-management | 2026 | Policy/log management via Apex Central | Doc |
| Trend Micro Apex One | C-11 | U | (no source found) | n/a | No recovery verification documented | Unknown |
| Trend Micro Apex One | C-12 | U | (no source found) | n/a | Resilience to management-plane outage not documented | Unknown |
| Bitdefender GravityZone | C-01 | P | https://www.bitdefender.com/en-us/business/products/managed-service-providers-security | 2026-10-05 | Prevention layers; offline not explicit | Doc |
| Bitdefender GravityZone | C-02 | P | https://techzone.bitdefender.com/en/security-layers/response/threat-response.html | 2026 | Policy-based automated response actions | Doc |
| Bitdefender GravityZone | C-03 | F | https://www.bitdefender.com/en-us/business/products/managed-service-providers-security | 2026-10-05 | XDR incident response across endpoints | Doc |
| Bitdefender GravityZone | C-04 | F | https://www.bitdefender.com/en-us/business/products/managed-service-providers-security | 2026-10-05 | Ransomware mitigation and rollback restores files | Doc |
| Bitdefender GravityZone | C-05 | P | https://www.bitdefender.com/en-us/business/products/managed-service-providers-security | 2026-10-05 | Audit-ready reporting; live/historical search | Doc |
| Bitdefender GravityZone | C-06 | U | (no source found) | n/a | No AI-agent runtime protection documented | Unknown |
| Bitdefender GravityZone | C-07 | F | https://www.bitdefender.com/en-us/business/products/managed-service-providers-security | 2026-10-05 | Multi-tenant parent-child console | Doc |
| Bitdefender GravityZone | C-08 | F | https://www.bitdefender.com/en-us/business/products/managed-service-providers-security | 2026-10-05 | Cloud MSP console | Doc |
| Bitdefender GravityZone | C-09 | P | https://techzone.bitdefender.com/en/security-layers/response/threat-response.html | 2026 | Integrity monitoring on Windows and Linux endpoints | Doc |
| Bitdefender GravityZone | C-10 | F | https://www.bitdefender.com/en-us/business/products/managed-service-providers-security | 2026-10-05 | Policy-based automated response, RBAC | Doc |
| Bitdefender GravityZone | C-11 | P | https://www.bitdefender.com/en-us/business/products/managed-service-providers-security | 2026-10-05 | Rollback restores files; no verification documented | Doc |
| Bitdefender GravityZone | C-12 | U | (no source found) | n/a | Resilience to management-plane outage not documented | Unknown |
| Elastic Security | C-01 | P | https://www.elastic.co/docs/solutions/security | 2026 | Endpoint prevention on host; cloud management | Doc |
| Elastic Security | C-02 | P | https://www.elastic.co/docs/reference/security/defend-advanced-settings | 2026 | Self-healing rollback and process termination on prevention alert | Doc |
| Elastic Security | C-03 | F | https://www.elastic.co/security | 2026 | Workflows automate response across systems | Doc |
| Elastic Security | C-04 | F | https://www.elastic.co/docs/reference/security/defend-advanced-settings | 2026 | Self-healing rollback (filesystem, registry, processes) | Doc |
| Elastic Security | C-05 | F | https://www.elastic.co/security-labs/blog/soc-case-management-detection-rule-history | 2026-08-03 | Immutable append-only rule history audit trail | Doc |
| Elastic Security | C-06 | U | (no source found) | n/a | No endpoint AI-agent runtime protection documented | Unknown |
| Elastic Security | C-07 | U | (no source found) | n/a | No native MSP multi-tenant console documented | Unknown |
| Elastic Security | C-08 | F | https://www.elastic.co/docs/solutions/security | 2026 | Self-managed or Elastic Cloud | Doc |
| Elastic Security | C-09 | F | https://www.elastic.co/security-labs/blog/linux-detection-engineering-with-auditd | 2024-04-09 | Linux detection engineering and auditd integration | Doc |
| Elastic Security | C-10 | F | https://www.elastic.co/security | 2026 | Detection rules, Workflows, approval gates | Doc |
| Elastic Security | C-11 | P | https://www.elastic.co/docs/reference/security/defend-advanced-settings | 2026 | Rollback self-healing; no verification documented | Doc |
| Elastic Security | C-12 | U | (no source found) | n/a | Resilience to management-plane outage not documented | Unknown |
| Wazuh (OSS) | C-01 | P | https://documentation.wazuh.com/current/user-manual/capabilities/active-response | 2026 | Active response scripts execute on endpoints; prevention via rules | Doc |
| Wazuh (OSS) | C-02 | P | https://documentation.wazuh.com/current/user-manual/capabilities/active-response | 2026 | Local scripts execute on triggering endpoint | Doc |
| Wazuh (OSS) | C-03 | P | https://documentation.wazuh.com/current/user-manual/capabilities/active-response | 2026 | Manager can run actions on all agents | Doc |
| Wazuh (OSS) | C-04 | P | https://documentation.wazuh.com/current/user-manual/capabilities/active-response | 2026 | Stateful responses revert after timeout; no rollback | Doc |
| Wazuh (OSS) | C-05 | P | https://documentation.wazuh.com/current/user-manual/capabilities/active-response | 2026 | Logs active responses; no tamper-evident ledger | Doc |
| Wazuh (OSS) | C-06 | U | (no source found) | n/a | No AI-agent runtime protection documented | Unknown |
| Wazuh (OSS) | C-07 | U | (no source found) | n/a | No native MSP multi-tenancy documented | Unknown |
| Wazuh (OSS) | C-08 | P | https://documentation.wazuh.com/current/user-manual/capabilities/active-response | 2026 | Self-managed (manager + agents) | Doc |
| Wazuh (OSS) | C-09 | F | https://documentation.wazuh.com/current/user-manual/capabilities/active-response | 2026 | Linux/Windows/macOS agents supported | Doc |
| Wazuh (OSS) | C-10 | P | https://documentation.wazuh.com/current/user-manual/capabilities/active-response | 2026 | Rule-based triggers; no staged policy governance | Doc |
| Wazuh (OSS) | C-11 | U | (no source found) | n/a | No recovery verification documented | Unknown |
| Wazuh (OSS) | C-12 | P | https://documentation.wazuh.com/current/user-manual/capabilities/active-response | 2026 | Manager-dependent; agent executes local scripts | Doc |
| AI-agent security products | C-01 | U | (no source found) | n/a | Not endpoint prevention products | Unknown |
| AI-agent security products | C-02 | P | https://docs.lakera.ai/docs/agent-security | 2026 | Runtime protection via Guard API flags/blocks agent actions | Doc |
| AI-agent security products | C-03 | U | (no source found) | n/a | Cross-endpoint not documented | Unknown |
| AI-agent security products | C-04 | U | (no source found) | n/a | No remediation/rollback documented | Unknown |
| AI-agent security products | C-05 | P | https://docs.lakera.ai/docs/agent-security | 2026 | Audit of guardrail decisions | Doc |
| AI-agent security products | C-06 | F | https://docs.lakera.ai/docs/agent-security | 2026 | Runtime protection for AI agents (prompt injection, tool calls) | Doc |
| AI-agent security products | C-07 | U | (no source found) | n/a | MSP multi-tenancy not documented | Unknown |
| AI-agent security products | C-08 | F | https://docs.lakera.ai/docs/agent-security | 2026 | Cloud API / SaaS | Doc |
| AI-agent security products | C-09 | U | (no source found) | n/a | Linux depth not applicable/documented | Unknown |
| AI-agent security products | C-10 | P | https://docs.lakera.ai/docs/agent-security | 2026 | Policy/guardrail configuration | Doc |
| AI-agent security products | C-11 | U | (no source found) | n/a | Recovery verification not documented | Unknown |
| AI-agent security products | C-12 | U | (no source found) | n/a | Resilience to mgmt-plane outage not documented | Unknown |

**Cell count: 120 (10 vendors x 12 capabilities). All cells cited or marked Unknown with reason.**

---

## 4. Gap hypotheses (ranked by buyer value and ease of proof)

| Rank | Hypothesis | Buyer value | Ease of proof | Kill test (head-to-head) |
|---|---|---|---|---|
| 1 | Verified recovery (rollback + verification of restored state) is not delivered by incumbents | High | Medium | Run ransomware simulator on 2 endpoints (ours vs SentinelOne rollback) and verify file integrity + hash of restored files; measure verification rate |
| 2 | Local autonomous response with verified recovery under management-plane outage is rare | High | Medium | Disconnect management plane; trigger detection; measure containment + recovery success vs CrowdStrike/SentinelOne |
| 3 | Tamper-evident evidence ledger export independently verifiable by auditor | Medium | High | Export ledger from our product and from vendor; auditor recomputes hashes; measure reproducibility |
| 4 | MSP multi-tenancy with per-tenant isolation and budget governance | Medium | Medium | Multi-tenant scenario: attempt cross-tenant data access; measure isolation and budget enforcement |
| 5 | Policy governance with staged rings and automatic halt on false-block spikes | Medium | High | Introduce bad policy in canary; measure halt and rollback timing vs vendor policy update |

---

## 5. Do-not-claim list

The company must **not** claim differentiation in areas where incumbents already deliver (documented):

- Offline prevention (CrowdStrike, SentinelOne, Sophos document full offline prevention).
- Automated malware cleanup/remediation (CrowdStrike, Microsoft, Bitdefender).
- Ransomware rollback (SentinelOne, Bitdefender, Elastic, Sophos CryptoGuard).
- Cross-endpoint response via SOAR/playbooks (CrowdStrike, Cortex XDR, Elastic).
- Audit logs/evidence trails (Microsoft, Cortex XDR, Elastic, CrowdStrike).
- MSP multi-tenancy (Cortex XDR, Bitdefender).
- AI-agent runtime protection (Microsoft Defender, Check Point/Lakera) — vendors already ship this; differentiate on governance/verification, not presence.
- Linux support (Elastic, Wazuh, CrowdStrike).
- Policy-driven automation (most vendors).

Differentiation should focus on: verified recovery, evidence-ledger external verifiability, management-plane resilience, and policy governance with staged rings/halt — subject to proof via kill tests.

---

## 6. Source register (unique URLs)

| # | Source | Date |
|---|---|---|
| 1 | https://www.crowdstrike.com/content/dam/crowdstrike/marketing/en-us/documents/pdfs/data-sheets/crowdstrike-falcon-prevent-data-sheet.pdf | 2026-08-24 |
| 2 | https://developer.crowdstrike.com/accomplish/automate-response | 2026 |
| 3 | https://www.crowdstrike.com/en-us/platform/endpoint-security/automated-remediation | 2026 |
| 4 | https://www.crowdstrike.com/en-us/blog/how-crowdstrike-automated-remediation-extends-flexible-response-capabilities | 2026 |
| 5 | https://developer.crowdstrike.com/api-reference/collections/real-time-response-audit | 2026 |
| 6 | https://learn.microsoft.com/en-us/defender-endpoint/automation-levels | 2025-04-04 |
| 7 | https://learn.microsoft.com/en-us/defender-endpoint/manage-auto-investigation | 2026-07-02 |
| 8 | https://learn.microsoft.com/en-us/defender-endpoint/automated-investigations | 2026-07-02 |
| 9 | https://learn.microsoft.com/en-us/defender-endpoint/auto-investigation-action-center | 2026-07-02 |
| 10 | https://learn.microsoft.com/defender-endpoint/ai-agent-runtime-protection-overview | 2026-10-08 |
| 11 | https://cortex-docs.paloaltonetworks.com/cortex-xdr-5.x/detect-investigate-and-respond-to-threats/investigate-and-respond-to-cases/response-actions | 2026 |
| 12 | https://cortex-docs.paloaltonetworks.com/cortex-xdr/insights-and-tips-cortex-xdr/security-operations-and-response/remediation-actions | 2026 |
| 13 | https://cortex-docs.paloaltonetworks.com/cortex-cloud-runtime-security/insights-and-tips-cortex-cloud/data-and-platform-administration/audit-logs | 2026 |
| 14 | https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR/Cortex-XDR-3.x-Documentation/What-is-Cortex-XDR-multi-tenant | 2026 |
| 15 | https://cortex-docs.paloaltonetworks.com/cortex-xdr/learn-about-cortex-xdr/readme-1/cortex-xdr-architecture | 2026 |
| 16 | https://www.paloaltonetworks.com/apps/pan/public/downloadResource?pagePath=/content/pan/en_US/resources/guides/acc-incident-response-using-cortex | 2026-05-12 |
| 17 | https://assets.sophos.com/X24WTUEQ/at/2b38x8h3fjg68jmm7tvbsp8m/sophos-intercept-x-ds.pdf | 2023-09-07 |
| 18 | https://www.sophos.com/en-us/products/endpoint-antivirus | 2025-06-02 |
| 19 | https://www.sophos.com/en-us/blog/new-innovations-in-sophos-endpoint-security | 2023-02-22 |
| 20 | https://docs.sophos.com/central/partner/help/en-us/Help/GlobalSettings/ProductsandServices/GlobalTemplates/BasePolicies/Endpoint/ConfigureMalwareProtection | 2026-09-16 |
| 21 | https://success.trendmicro.com/en-US/solution/KA-0011866 | 2026-02-27 |
| 22 | https://docs.trendmicro.com/en-us/documentation/article/trend-micro-apex-one-patch-3-online-help-log-management | 2026 |
| 23 | https://docs.trendmicro.com/en-us/documentation/apex-one-as-a-service | 2026 |
| 24 | https://www.bitdefender.com/en-us/business/products/managed-service-providers-security | 2026-10-05 |
| 25 | https://techzone.bitdefender.com/en/security-layers/response/threat-response.html | 2026 |
| 26 | https://www.elastic.co/docs/solutions/security | 2026 |
| 27 | https://www.elastic.co/docs/reference/security/defend-advanced-settings | 2026 |
| 28 | https://www.elastic.co/security-labs/blog/soc-case-management-detection-rule-history | 2026-08-03 |
| 29 | https://www.elastic.co/security-labs/blog/linux-detection-engineering-with-auditd | 2024-04-09 |
| 30 | https://www.elastic.co/security | 2026 |
| 31 | https://documentation.wazuh.com/current/user-manual/capabilities/active-response | 2026 |
| 32 | https://docs.lakera.ai/docs/agent-security | 2026 |
| 33 | https://cyberstrategyinstitute.com/sentinelone-singularity-review | 2026-10-05 |
| 34 | https://www.sentinelone.com/platform/endpoint-security | 2026 |
| 35 | https://www.sentinelone.com/press/sentinelone-makes-the-autonomous-soc-trustworthy-with-governed-closed-loop-response | 2026-08-03 |
| 36 | https://www.sentinelone.com/press/sentinelone-opens-purple-ai-agentic-investigation-to-all-customers-bringing-frontier-ai-directly-into-the-soc | 2026-06-17 |
| 37 | https://www.sentinelone.com/faq | 2026 |
| 38 | https://www.sentinelone.com/platform/singularity-complete | 2026 |

---

## Contract Closure

1. **Deliverables produced:**
   - Capability definitions (§1, 12)
   - Vendor list (10)
   - Capability matrix (§2)
   - Cell citations (§3, 120 cells)
   - Gap hypotheses with kill tests (§4, 5)
   - Do-not-claim list (§5)
   - Source register (§6, 38 sources)

2. **Acceptance checks:**
   - At least 10 offerings: **PASS** (10)
   - At least 12 capabilities: **PASS** (12)
   - No uncited cell: **PASS** (all 120 cells cited or marked Unknown with reason)
   - Every hypothesis has falsification test: **PASS** (§4)
   - Sources dated: **PASS** (§6)

3. **Assumptions made:** Validation assessment candidate differentiators not supplied (OQ-01); levels based on public documentation/marketing; Unknown used where no source.

4. **Open questions:**
   - OQ-01: The five candidate differentiators from the validation assessment were not supplied; gap hypotheses derived from matrix instead.
   - OQ-02: Some cells marked Unknown due to lack of public documentation; may change with deeper research.
   - OQ-03: Vendor capabilities evolve rapidly; matrix should be refreshed before any external claim.

5. **Out-of-scope items noticed (not acted on):** pricing, positioning copy, architecture changes.

6. **Handoff:** Consumed by P0.9 and P0.11. IDs to preserve: C-01..C-12, GH-01..GH-05, V-01..V-10.
