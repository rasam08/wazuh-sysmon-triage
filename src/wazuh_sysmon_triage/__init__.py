"""
wazuh_sysmon_triage package.

This package provides functionality for triaging Sysmon data in conjunction with Wazuh alerts.
"""

__version__ = "2.0.0"
__author__ = "Rasam Moghaddam"
__email__ = "rasammgg@gmail.com"

from wazuh_sysmon_triage.output_schema import OUTPUT_SCHEMA_VERSION

__all__ = [
    "__version__",
    "__author__",
    "__email__",
    "OUTPUT_SCHEMA_VERSION",
]
