import argparse
import ipaddress
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from config import Config
from switch_monitor import read_switch


def main():
    parser = argparse.ArgumentParser(
        description="Read raw SNMP system uptime and interface labels/status from a switch."
    )
    parser.add_argument("ip", help="Switch IP address")
    args = parser.parse_args()

    try:
        ip = str(ipaddress.ip_address(args.ip))
    except ValueError:
        parser.error("ip must be a valid IP address")
    if not Config.SWITCH_SNMP_COMMUNITY:
        parser.error("Set SWITCH_SNMP_COMMUNITY in the local .env file first")

    try:
        result = read_switch(ip, Config.SWITCH_SNMP_COMMUNITY)
    except (OSError, RuntimeError, TimeoutError) as error:
        parser.exit(
            1,
            f"SNMP check failed ({type(error).__name__}: {error}). "
            "Check switch reachability and SNMP settings.\n",
        )

    print(f"Switch: {ip}")
    print(f"sysUpTime: {result['sysUpTime'] or '<not returned>'}")
    if not result["interfaces"]:
        print("No IF-MIB interface rows returned.")
    for interface in result["interfaces"]:
        print(
            f"ifIndex={interface['ifIndex']} "
            f"ifName={interface['ifName'] or '<not returned>'} "
            f"ifDescr={interface['ifDescr'] or '<not returned>'} "
            f"ifOperStatus={interface['ifOperStatus'] or '<not returned>'}"
        )


if __name__ == "__main__":
    main()
