# File: /wazuh-sysmon-triage/wazuh-sysmon-triage/src/wazuh_sysmon_triage/__main__.py

from wazuh_sysmon_triage.cli import app


def main() -> None:
    """Entry point for the CLI tool."""
    app()


if __name__ == "__main__":
    main()
