# lldp

Mythic C2 profile for peer-to-peer communication over IEEE 802.1AB (LLDP). C2 data is carried inside Organizationally Specific TLVs (Type 127) with a configurable OUI so that frames blend with vendor-specific LLDP extensions on the wire.

LLDP is Layer 2 only. Both agents must share a broadcast domain. An egress agent (HTTP/HTTPX) bridges LLDP-linked agents back to the Mythic server, same as the SMB and TCP P2P profiles.

## Supported agents

| Agent | Linux | Windows |
|:------|:------|:--------|
| [Starburst](https://github.com/Whispergate/Starburst) | AF_PACKET raw sockets | Npcap (`wpcap.dll`) |

## Installation

```bash
sudo ./mythic-cli install github https://github.com/Whispergate/lldp
```

If Mythic is already running:

```bash
sudo ./mythic-cli c2 start lldp
```

Or restart everything:

```bash
sudo ./mythic-cli mythic start
```

## Configuration

| Parameter | Default | Description |
|:----------|:--------|:------------|
| `oui_profile` | Cisco (00:00:0C) | Vendor OUI preset for the Org-Specific TLV |
| `oui_custom` | — | Custom 3-byte OUI as 6 hex chars. Used when `oui_profile` is "Custom" |
| `subtype` | `01` | 1-byte TLV subtype (hex). Both ends must match |
| `AESPSK` | aes256_hmac | Encryption mode |
| `encrypted_exchange_check` | true | Perform key exchange on link establishment |
| `killdate` | +365 days | Agent expiry date |

## Requirements

* **Linux**: `CAP_NET_RAW` + `CAP_NET_ADMIN` (or root)
* **Windows**: Npcap installed. The agent resolves `wpcap.dll` at runtime

## config.json

```json
{
  "exclude_payload_type": true,
  "exclude_c2_profiles": false,
  "exclude_documentation_payload": true,
  "exclude_documentation_c2": false,
  "exclude_agent_icons": true
}
```

## Authors

- [@Lavender-exe](https://github.com/Lavender-exe)
- [@Mymaqn](https://github.com/Mymaqn) — initial idea

## References

- [IEEE Std 802.1AB LLDP for IETF LSVR Neighbor Discovery and Configuration](https://www.ieee802.org/1/files/public/docs2025/new-bottorff-lldp-tlvs-for-lsvr-0425-v00.pdf)
- [Hilscher - Link Layer Discovery Protocol (LLDP)](https://www.hilscher.com/service-support/glossary/link-layer-discovery-protocol-lldp)
- [Wikipedia - Link Layer Discovery Protocol](https://en.wikipedia.org/wiki/Link_Layer_Discovery_Protocol)