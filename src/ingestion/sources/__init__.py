"""Conectores concretos, uno por fuente OSINT."""

from .cisa_kev import CisaKevConnector
from .otx import OtxConnector
from .threatfox import ThreatFoxConnector

#: Orden deliberado: KEV primero porque es verdad dura y barata de consultar.
ALL_CONNECTORS = (CisaKevConnector, ThreatFoxConnector, OtxConnector)

__all__ = ["CisaKevConnector", "OtxConnector", "ThreatFoxConnector", "ALL_CONNECTORS"]
