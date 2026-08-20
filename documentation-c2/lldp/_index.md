+++
title = "lldp"
chapter = false
weight = 5
+++

## Summary

P2P C2 profile over IEEE 802.1AB (LLDP). Agents on the same Ethernet segment exchange C2 messages inside Organizationally Specific TLVs (Type 127) with a configurable OUI. On the wire, this looks like normal vendor-specific LLDP extensions.

LLDP is Layer 2 only (no IP routing), so both agents must share a broadcast domain. An egress agent (HTTP/HTTPX) bridges LLDP-linked agents to the Mythic server, same as the SMB and TCP P2P profiles.

Wire format:

| Byte Size            | Meaning                                                                                  |
|:---------------------|:-----------------------------------------------------------------------------------------|
| 6 Bytes              | Destination MAC (LLDP multicast 01:80:C2:00:00:0E or peer unicast)                      |
| 6 Bytes              | Source MAC (interface MAC of the sending agent)                                           |
| 2 Bytes              | EtherType 0x88CC                                                                         |
| variable             | Mandatory TLVs: Chassis ID (MAC), Port ID (local), TTL (120s)                            |
| 2 Bytes              | Org-Specific TLV header (Type=127, Length)                                               |
| 3 Bytes              | OUI (configurable vendor spoof)                                                          |
| 1 Byte               | OUI Subtype (configurable)                                                               |
| 4 Bytes              | Message ID (uint32 big-endian, identifies a multi-frame message)                         |
| 2 Bytes              | Sequence number (uint16 big-endian, chunk index starting at 0)                           |
| 2 Bytes              | Total chunks (uint16 big-endian)                                                         |
| 0-499 Bytes          | Chunk payload (raw bytes of the base64 Mythic message fragment)                          |
| (repeat TLV block)   | Up to 3 Org-Specific TLVs per frame (multi-TLV packing)                                 |
| 2 Bytes              | End of LLDPDU TLV (0x0000)                                                               |

Up to 3 Org-Specific TLVs are packed into a single Ethernet frame (multi-TLV packing). This doubles throughput for large messages compared to one TLV per frame. The frame budget is 1514 bytes total; after mandatory headers (34 bytes) and the End TLV (2 bytes), 1478 bytes remain for Org-Specific TLVs. Each TLV costs 2 bytes header + 3 OUI + 1 subtype + 8 chunk header + payload, so a full 499-byte chunk uses 513 bytes. Two full TLVs fit per frame (1026 bytes); a third gets up to 438 bytes of payload.

Messages larger than 499 bytes are chunked across TLVs and frames sharing the same Message ID. The receiver reassembles by sequence number and delivers the complete message once all chunks arrive. After reassembly, the payload uses the standard Mythic format: `base64(uuid + encrypted_data)`.

If this is the callback that generated the message, then it is the same message you would send through an egress profile. If you are another callback in a chain:

* from somebody further away from egress - bundle it as a delegate message and forward it closer to egress
* from the direction of egress - it is a message for you, process it directly

## OUI Vendor Spoofing

The OUI in the Org-Specific TLV is configurable. Setting it to a known vendor makes the C2 frames look like that vendor's LLDP extensions. Available presets:

| Preset               | OUI      | Use Case                                                         |
|:---------------------|:---------|:-----------------------------------------------------------------|
| Cisco                | 00:00:0C | Enterprise switches and routers (most common)                    |
| Aruba/HPE            | 00:0B:86 | Campus and wireless networks                                     |
| Juniper              | 00:05:85 | Data center switches and routers                                 |
| Arista               | 00:1C:73 | Data center leaf/spine switches                                  |
| Dell                 | 00:14:22 | Servers and PowerSwitch                                          |
| VMware               | 00:50:56 | Virtual NICs (expected in virtualized environments)              |
| Ubiquiti             | FC:EC:DA | SMB/campus wireless and switches                                 |
| MikroTik             | D4:CA:6D | Routers, common in ISP/SMB networks                             |
| Samsung              | 00:16:32 | IoT and embedded devices                                         |
| IANA/IETF            | 00:00:5E | Official IETF OUI per RFC 7042                                   |
| Custom               | (user)   | Operator-supplied 3-byte OUI                                     |

## Configuration

### oui_profile

Which vendor OUI to place in Org-Specific TLVs. Defaults to Cisco. Select "Custom" to provide your own OUI.

### oui_custom

A custom 3-byte OUI as 6 hexadecimal characters (e.g. `DEAD01`). Only used when `oui_profile` is set to "Custom". Must match the regex `^[0-9a-fA-F]{6}$`.

### subtype

The 1-byte Org-Specific TLV subtype as 2 hexadecimal characters. Identifies C2 data within the OUI namespace. Defaults to `01`. Both ends of a link must match.

### killdate

When the agent should stop executing.

### encrypted_exchange_check

True or False if this agent should do a key exchange during initial link establishment.

### AESPSK

Either an aes256_hmac key to use for encryption or no encryption at all.

## Requirements

Raw Ethernet socket access is required on both platforms:

* **Linux**: `CAP_NET_RAW` and `CAP_NET_ADMIN` (or root). Uses `AF_PACKET` sockets with `ETH_P_LLDP` (0x88CC).
* **Windows**: Npcap installed. The agent loads `wpcap.dll` at runtime (falls back to `C:\Windows\System32\Npcap\wpcap.dll`). Adapter discovery uses `pcap_findalldevs`; peer MAC resolution uses `SendARP` from `iphlpapi.dll`.

Both agents must share a Layer 2 broadcast domain (same VLAN/subnet). LLDP is not routable.

## Detections

### Network

* **LLDP from non-network-equipment MACs.** Legitimate LLDP originates from switches, routers, and APs. An LLDP frame (EtherType 0x88CC, dst 01:80:C2:00:00:0E) sourced from a workstation, server, or VM NIC OUI is anomalous. Alert on source MACs outside your known infrastructure vendor list.
* **LLDP frame rate and volume.** Real LLDP speakers send one frame every 30 seconds (default timer per IEEE 802.1AB). C2 traffic produces bursts of many frames in quick succession during message exchange. A spike of >5 LLDP frames/second from a single source, or sustained LLDP traffic between two endpoints, is suspicious.
* **Org-Specific TLV payload size.** Normal vendor Org-Specific TLVs are short (tens of bytes of structured data). C2 chunks fill up to 499 bytes per TLV. Frames consistently carrying large Org-Specific TLVs stand out.
* **Multi-frame messages.** Legitimate LLDP does not fragment data across frames with sequence numbers. Any Org-Specific TLV containing what looks like a chunk header (message ID + sequence + total fields) is not standard LLDP behavior.
* **OUI mismatch.** If the Org-Specific TLV claims a Cisco OUI (00:00:0C) but the source MAC belongs to a Dell server NIC, the frame is spoofed. Correlate the TLV's OUI against the source MAC's registered vendor.
* **LLDP between endpoints.** LLDP is normally unidirectional: a switch port advertises to the host. Two hosts exchanging LLDP frames with each other (bidirectional 0x88CC traffic on a non-trunk port) is not expected.

### Linux host

* **`AF_PACKET` socket with `ETH_P_LLDP`.** Processes opening raw packet sockets filtered to protocol 0x88CC. Audit with `ss --packet` or watch for `socket(AF_PACKET, SOCK_RAW, ...)` in syscall tracing (auditd, sysdig, eBPF). Normal userland processes do not open LLDP raw sockets; `lldpd` is the main exception.
* **Capabilities on non-standard binaries.** Any binary with `CAP_NET_RAW` or `CAP_NET_ADMIN` that is not a known network daemon. Check with `getcap` or audit `capset`/`prctl` syscalls.
* **Unexpected `SO_BINDTODEVICE`.** The agent binds its raw socket to a specific interface. `setsockopt(..., SO_BINDTODEVICE, ...)` from a process that is not a network service is unusual.

### Windows host

* **`wpcap.dll` loaded by non-network-tools.** The agent calls `LoadLibraryA("wpcap.dll")` or loads from `C:\Windows\System32\Npcap\wpcap.dll`. Sysmon Event ID 7 (Image Loaded) for `wpcap.dll` in a process that is not Wireshark, Nmap, or another known pcap consumer is suspicious.
* **Npcap API calls from unexpected processes.** `pcap_open_live`, `pcap_sendpacket`, `pcap_next_ex` resolved via `GetProcAddress`. Monitor for `GetProcAddress` resolving pcap symbols in processes that should not need packet capture.
* **`SendARP` from `iphlpapi.dll`.** The agent uses `SendARP` to resolve a target IP to a MAC address before initiating the LLDP link. ARP resolution from a non-network-management process can indicate lateral movement preparation.
* **Npcap driver access.** Npcap's `npcap` service and `\\.\Global\NPCAP` device are accessed when opening a capture handle. ETW or Sysmon can flag processes opening this device that are not in an allowlist.

### SIEM rules (summary)

| Detection | Data source | Logic |
|:----------|:------------|:------|
| LLDP from workstation MAC | Span port / TAP, Zeek `lldp.log` | src MAC OUI not in network-equipment allowlist |
| LLDP burst | Span port / TAP | >5 frames/sec from one source with EtherType 0x88CC |
| OUI mismatch | Span port / TAP | Org-Specific TLV OUI does not match source MAC vendor |
| Raw LLDP socket (Linux) | auditd, Falco, eBPF | `socket(AF_PACKET, SOCK_RAW, 0x88CC)` by non-lldpd process |
| wpcap.dll side-load (Windows) | Sysmon Event 7 | `wpcap.dll` loaded by process outside allowlist |
| SendARP from user process (Windows) | Sysmon, ETW | `SendARP` call from non-admin-tool process |

## Authors

- @Lavender-exe
- @Mymaqn - Initial Idea

## References

- [IEEE Std 802.1AB LLDP for IETF LSVR Neighbor Discovery and Configuration](https://www.ieee802.org/1/files/public/docs2025/new-bottorff-lldp-tlvs-for-lsvr-0425-v00.pdf)
- [Hilscher - Link Layer Discovery Protocol (LLDP)](https://www.hilscher.com/service-support/glossary/link-layer-discovery-protocol-lldp)
- [Wikipedia - Link Layer Discovery Protocol](https://en.wikipedia.org/wiki/Link_Layer_Discovery_Protocol)