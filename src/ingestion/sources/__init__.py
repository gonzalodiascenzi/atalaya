"""Conectores concretos, uno por fuente OSINT."""

from .cisa_kev import CisaKevConnector
from .emerging_threats import EmergingThreatsConnector
from .otx import OtxConnector
from .spamhaus_drop import SpamhausDropConnector
from .threatfox import ThreatFoxConnector

#: Fuentes que GENERAN misiones. KEV primero: es verdad dura y barata.
#: Spamhaus no está acá a propósito: no genera, corrobora (ver run.py).
ALL_CONNECTORS = (
    CisaKevConnector,
    ThreatFoxConnector,
    EmergingThreatsConnector,
    OtxConnector,
)

__all__ = [
    "CisaKevConnector",
    "EmergingThreatsConnector",
    "OtxConnector",
    "SpamhausDropConnector",
    "ThreatFoxConnector",
    "ALL_CONNECTORS",
]
