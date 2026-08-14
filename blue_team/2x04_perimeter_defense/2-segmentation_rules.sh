#!/bin/bash

set -euo pipefail

OUTPUT_FILE="${1:-segmentation_rules.json}"

if ! command -v jq >/dev/null 2>&1; then
    printf 'Error: required command not found: jq\n' >&2
    exit 1
fi

# Four zones: DMZ, INTERNAL, MGMT and MEDDEV.
# Every zone uses default_inbound drop and default_outbound accept with
# specific restrictions. Allow rules precede the final deny_all rules.
# No flows from MEDDEV to DMZ or the public Internet.
# No flows from any zone into MEDDEV except MGMT on tcp/22 and tcp/4242.
jq -n '
    {
        zones: [
            {
                name: "DMZ",
                cidr: "10.10.20.0/24",
                purpose: "Public-facing web and application services",
                default_inbound: "drop",
                default_outbound: "accept",
                outbound_restrictions: [
                    "Only named application hosts may access INTERNAL databases on tcp/3306",
                    "No direct access to MGMT or MEDDEV"
                ],
                named_hosts: [
                    {name: "web-srv-01", ip: "10.10.20.10"},
                    {name: "api-srv-01", ip: "10.10.20.11"}
                ]
            },
            {
                name: "INTERNAL",
                cidr: "10.10.30.0/24",
                purpose: "Clinical workstations, EHR applications and database servers",
                default_inbound: "drop",
                default_outbound: "accept",
                outbound_restrictions: [
                    "Clinical workstations may reach INTERNAL servers only on tcp/443 and tcp/3306",
                    "No direct access into MEDDEV"
                ],
                address_groups: {
                    clinical_workstations: "10.10.30.0/25",
                    server_hosts: "10.10.30.128/25"
                }
            },
            {
                name: "MGMT",
                cidr: "10.10.40.0/24",
                purpose: "Administrative workstations, management services and DNS resolvers",
                default_inbound: "drop",
                default_outbound: "accept",
                outbound_restrictions: [
                    "Administrative SSH is limited to approved zone flows",
                    "Medical-device management is limited to tcp/22 and tcp/4242"
                ],
                named_hosts: [
                    {name: "dns-mgmt-01", ip: "10.10.40.53"}
                ]
            },
            {
                name: "MEDDEV",
                cidr: "10.10.50.0/24",
                purpose: "Medical imaging and clinical devices",
                default_inbound: "drop",
                default_outbound: "accept",
                outbound_restrictions: [
                    "Only tcp/4242 DICOM and tcp/443 EHR traffic may reach INTERNAL",
                    "Only DNS tcp/53 and udp/53 may reach the MGMT resolver",
                    "No access to DMZ",
                    "No access to the public Internet"
                ]
            }
        ],
        flows: [
            {
                action: "allow",
                src_zone: "MGMT",
                dst_zone: "INTERNAL",
                proto: "tcp",
                dport: 22,
                justification: "SSH administration of internal servers",
                exception_for: null
            },
            {
                action: "allow",
                src_zone: "MGMT",
                dst_zone: "DMZ",
                proto: "tcp",
                dport: 22,
                justification: "SSH administration of DMZ servers",
                exception_for: null
            },
            {
                action: "allow",
                src_zone: "INTERNAL",
                dst_zone: "INTERNAL",
                src_group: "clinical_workstations",
                dst_group: "server_hosts",
                proto: "tcp",
                dport: 443,
                justification: "Clinical workstation access to internal HTTPS applications",
                exception_for: null
            },
            {
                action: "allow",
                src_zone: "INTERNAL",
                dst_zone: "INTERNAL",
                src_group: "clinical_workstations",
                dst_group: "server_hosts",
                proto: "tcp",
                dport: 3306,
                justification: "Clinical application access to internal MySQL services",
                exception_for: null
            },
            {
                action: "allow",
                src_zone: "DMZ",
                dst_zone: "INTERNAL",
                src_hosts: [
                    {name: "web-srv-01", ip: "10.10.20.10"},
                    {name: "api-srv-01", ip: "10.10.20.11"}
                ],
                dst_group: "database_servers",
                proto: "tcp",
                dport: 3306,
                justification: "Named DMZ application hosts access internal databases",
                exception_for: null
            },
            {
                action: "allow",
                src_zone: "MEDDEV",
                dst_zone: "INTERNAL",
                dst_group: "pacs_servers",
                proto: "tcp",
                dport: 4242,
                justification: "DICOM imaging to PACS",
                exception_for: null
            },
            {
                action: "allow",
                src_zone: "MEDDEV",
                dst_zone: "INTERNAL",
                dst_group: "ehr_web_servers",
                proto: "tcp",
                dport: 443,
                justification: "EHR web integration for device display",
                exception_for: null
            },
            {
                action: "allow",
                src_zone: "ALL",
                dst_zone: "MGMT",
                dst_hosts: [{name: "dns-mgmt-01", ip: "10.10.40.53"}],
                proto: "udp",
                dport: 53,
                justification: "DNS resolution through the management resolver",
                exception_for: null
            },
            {
                action: "allow",
                src_zone: "ALL",
                dst_zone: "MGMT",
                dst_hosts: [{name: "dns-mgmt-01", ip: "10.10.40.53"}],
                proto: "tcp",
                dport: 53,
                justification: "DNS TCP fallback through the management resolver",
                exception_for: null
            },
            {
                action: "allow",
                src_zone: "MGMT",
                dst_zone: "MEDDEV",
                proto: "tcp",
                dport: 22,
                justification: "SSH administration of supported medical devices",
                exception_for: null
            },
            {
                action: "allow",
                src_zone: "MGMT",
                dst_zone: "MEDDEV",
                proto: "tcp",
                dport: 4242,
                justification: "DICOM service validation and medical-device management",
                exception_for: null
            },

            {action:"deny_all",src_zone:"DMZ",dst_zone:"INTERNAL",proto:"any",dport:"any",justification:"Deny all other DMZ to INTERNAL traffic",exception_for:null},
            {action:"deny_all",src_zone:"DMZ",dst_zone:"MGMT",proto:"any",dport:"any",justification:"No DMZ access to management systems",exception_for:null},
            {action:"deny_all",src_zone:"DMZ",dst_zone:"MEDDEV",proto:"any",dport:"any",justification:"No DMZ access to medical devices",exception_for:null},
            {action:"deny_all",src_zone:"INTERNAL",dst_zone:"DMZ",proto:"any",dport:"any",justification:"No unspecified INTERNAL to DMZ traffic",exception_for:null},
            {action:"deny_all",src_zone:"INTERNAL",dst_zone:"MGMT",proto:"any",dport:"any",justification:"Only DNS through the named MGMT resolver is permitted",exception_for:null},
            {action:"deny_all",src_zone:"INTERNAL",dst_zone:"MEDDEV",proto:"any",dport:"any",justification:"No INTERNAL access into MEDDEV",exception_for:null},
            {action:"deny_all",src_zone:"INTERNAL",dst_zone:"INTERNAL",proto:"any",dport:"any",justification:"Deny unapproved lateral traffic between internal roles",exception_for:null},
            {action:"deny_all",src_zone:"MGMT",dst_zone:"DMZ",proto:"any",dport:"any",justification:"Deny non-administrative MGMT to DMZ traffic",exception_for:null},
            {action:"deny_all",src_zone:"MGMT",dst_zone:"INTERNAL",proto:"any",dport:"any",justification:"Deny non-administrative MGMT to INTERNAL traffic",exception_for:null},
            {action:"deny_all",src_zone:"MGMT",dst_zone:"MEDDEV",proto:"any",dport:"any",justification:"Only MGMT tcp/22 and tcp/4242 may enter MEDDEV",exception_for:null},
            {action:"deny_all",src_zone:"MEDDEV",dst_zone:"DMZ",proto:"any",dport:"any",justification:"Medical devices must not access the DMZ",exception_for:null},
            {action:"deny_all",src_zone:"MEDDEV",dst_zone:"INTERNAL",proto:"any",dport:"any",justification:"Only MEDDEV tcp/4242 and tcp/443 may reach INTERNAL",exception_for:null},
            {action:"deny_all",src_zone:"MEDDEV",dst_zone:"MGMT",proto:"any",dport:"any",justification:"Only DNS to the named MGMT resolver is permitted",exception_for:null},
            {action:"deny_all",src_zone:"MEDDEV",dst_zone:"INTERNET",proto:"any",dport:"any",justification:"Medical devices must not access the public Internet",exception_for:null},
            {action:"deny_all",src_zone:"ALL",dst_zone:"MGMT",proto:"any",dport:"any",justification:"Only tcp/53 and udp/53 may reach the named MGMT resolver",exception_for:null}
        ]
    }
    | .summary = {
        flow_count: (.flows | length),
        allow_count: ([.flows[] | select(.action == "allow")] | length),
        deny_count: ([.flows[] | select(.action == "deny_all")] | length),
        cross_zone_pair_count: ([.flows[] | select(.src_zone != .dst_zone) | [.src_zone, .dst_zone]] | unique | length),
        cross_zone_pairs: ([.flows[] | select(.src_zone != .dst_zone) | (.src_zone + "->" + .dst_zone)] | unique)
    }
' > "$OUTPUT_FILE"

printf 'Segmentation rules written to %s\n' "$OUTPUT_FILE"
jq '.summary' "$OUTPUT_FILE"