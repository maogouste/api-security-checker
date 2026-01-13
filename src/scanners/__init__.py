"""Security scanners."""

from .api.auth import AuthScanner
from .api.injection import InjectionScanner
from .api.graphql import GraphQLScanner
from .api.bola import BOLAScanner
from .api.exposure import DataExposureScanner
from .api.mass_assignment import MassAssignmentScanner
from .api.legacy import LegacyAPIScanner
from .api.logging import LoggingScanner
from .recon.known_files import KnownFilesScanner
from .recon.endpoints import EndpointsScanner
from .recon.headers import HeadersScanner
from .recon.fuzzer import FuzzerScanner

__all__ = [
    # API Vulnerability Scanners (V01-V10)
    "AuthScanner",          # V02, V04
    "BOLAScanner",          # V01
    "DataExposureScanner",  # V03
    "MassAssignmentScanner",  # V05
    "InjectionScanner",     # V06, V07
    "LegacyAPIScanner",     # V09
    "LoggingScanner",       # V10
    # GraphQL Scanner (G01-G05)
    "GraphQLScanner",
    # Reconnaissance Scanners
    "HeadersScanner",       # V08
    "KnownFilesScanner",
    "EndpointsScanner",
    "FuzzerScanner",
]
