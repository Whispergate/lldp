import os
from pathlib import Path

from mythic_container.C2ProfileBase import (
    C2Profile,
    C2ProfileParameter,
    ParameterType,
)


class LLDP(C2Profile):
    name = "lldp"
    description = "P2P communication over LLDP (IEEE 802.1AB) Organizationally Specific TLVs."
    author = "@Lavender-exe"
    is_p2p = True
    is_server_routed = True
    semver = "0.1.0"
    server_binary_path = Path(os.path.join(".", "lldp", "c2_code"))
    server_folder_path = Path(os.path.join(".", "lldp", "c2_code"))
    parameters = [
        C2ProfileParameter(
            name="oui_profile",
            description="Vendor OUI to spoof in Org-Specific TLVs. Frames appear as if originating from the selected vendor's equipment.",
            default_value="Cisco (00000C)",
            parameter_type=ParameterType.ChooseOne,
            choices=[
                "Cisco (00000C)",
                "Aruba/HPE (000B86)",
                "Juniper (000585)",
                "Arista (001C73)",
                "Dell (001422)",
                "VMware (005056)",
                "Ubiquiti (FCECDA)",
                "MikroTik (D4CA6D)",
                "Samsung (001632)",
                "IANA/IETF (00005E)",
                "Custom",
            ],
            required=False,
        ),
        C2ProfileParameter(
            name="oui_custom",
            description="Custom 3-byte OUI as 6 hex characters (e.g. DEAD01). Used only when oui_profile is set to Custom.",
            default_value="",
            required=False,
            verifier_regex="^([0-9a-fA-F]{6})?$",
        ),
        C2ProfileParameter(
            name="subtype",
            description="1-byte Org-Specific TLV subtype as 2 hex characters. Identifies C2 data TLVs within the OUI namespace.",
            default_value="01",
            required=False,
            verifier_regex="^[0-9a-fA-F]{2}$",
        ),
        C2ProfileParameter(
            name="AESPSK",
            description="Encryption type for agent communication.",
            default_value="aes256_hmac",
            parameter_type=ParameterType.ChooseOne,
            choices=["aes256_hmac", "none"],
            crypto_type=True,
            required=False,
        ),
        C2ProfileParameter(
            name="encrypted_exchange_check",
            description="Perform encrypted key exchange during initial link.",
            default_value=True,
            parameter_type=ParameterType.Boolean,
            required=False,
        ),
        C2ProfileParameter(
            name="peer_ip",
            description="IP address of the egress agent. The child resolves this via ARP to send directed LLDP frames instead of broadcast. Leave empty for broadcast.",
            default_value="",
            required=False,
        ),
        C2ProfileParameter(
            name="killdate",
            description="Date after which the agent stops communicating.",
            default_value=365,
            parameter_type=ParameterType.Date,
            required=False,
        ),
    ]
