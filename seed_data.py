"""Starting inventory, taken from the hardware spreadsheet (names, roles, IPs only).

No usernames or passwords are copied here on purpose.
"""

# name, ip, cpu %, memory %, disk %, temperature C, uptime hours
HOSTS = [
    ("TSHSER001", "192.168.8.237", 32, 64, 58, 42, 32 * 24 + 14),
    ("TSHSER002", "192.168.9.18", 84, 72, 67, 56, 18 * 24 + 6),
    ("TSHSER003", "192.168.8.99", 46, 61, 48, 44, 45 * 24 + 11),
]

# parent host -> list of (name, role, ip)  (ip None = "Not set")
VMS = {
    "TSHSER001": [
        ("TSHMCVS1", "Materials Controls", "192.168.9.79"),
        ("TSHDTSVS4", "Directors Terminal Service", None),
        ("TSHSSVS3", "Sunsystems", "192.168.8.101"),
        ("TSHOXIVS", "Oxi Server", "192.168.8.112"),
        ("TSHANTVS1", "Meru Terminal Service", "192.168.9.85"),
    ],
    "TSHSER002": [
        ("TSHDMNVS4", "Domain Controller", "192.168.8.90"),
        ("TSHHRBVS3", "HR Paymaster", "192.168.8.183"),
        ("TSHOPRHMVS2", "Opera Hotel Mobile", "192.168.9.130"),
        ("TSHOSVS7", "Opera", "192.168.8.125"),
        ("TSHRPTVS5", "Repository ICT Files", "192.168.8.91"),
        ("TSHTMNVS6", "Terminal Service / Backup Folders", "192.168.8.167"),
        ("TSHBAVS6", "Biometric Access Server", "192.168.8.241"),
    ],
    "TSHSER003": [
        ("TSHCAPVS2", "Caps", "192.168.8.55"),
        ("TSHIWSSVS3", "Interface Workstation", "192.168.8.54"),
        ("TSHMSVS4", "Micros Symphony", "192.168.8.53"),
        ("TSHMSVS5", "Micros Symphony", "192.168.8.249"),
        ("TSHQEMSVS1", "QEMS Server", "192.168.8.151"),
        ("TSHHTZVS1", "Hoteza (Linux based)", None),
        ("TSHVINGVS5", "Vingcard", "192.168.8.56"),
    ],
}

# name, role, ip, type
OTHER_DEVICES = [
    ("CASASERVER", "CasaServer (ASRock)", "192.168.8.154", "server"),
    ("TSHSYNOLOGY", "Synology NAS", "192.168.8.27", "storage"),
    ("CORE-SWITCH", "Core switch", "10.10.0.9", "switch"),
    ("SW-B1", "Floor switch - Basement 1 (ICX 7150-48P)", "10.10.0.62", "switch"),
    ("SW-GROUND", "Floor switch - Ground (ICX 7150-48P)", "10.10.0.60", "switch"),
    ("SW-1ST", "Floor switch - 1st floor (ICX 7150-48P)", "10.10.0.61", "switch"),
    ("SW-2ND", "Floor switch - 2nd floor (ICX 7150-48P)", "10.10.0.69", "switch"),
    ("SW-3RD", "Floor switch - 3rd floor (ICX 7150-48P)", "10.10.0.67", "switch"),
    ("SW-4TH", "Floor switch - 4th floor (ICX 7150-48P)", "10.10.0.70", "switch"),
    ("SW-5TH", "Floor switch - 5th floor (ICX 7150-48P)", "10.10.0.64", "switch"),
    ("CAM-SW-B1", "Camera switch - Basement 1", "192.168.2.210", "switch"),
    ("CAM-SW-GROUND", "Camera switch - Ground", "192.168.2.201", "switch"),
    ("CAM-SW-2ND", "Camera switch - 2nd floor", "192.168.2.202", "switch"),
    ("CAM-SW-CONTROL", "Camera switch - Control room", "192.168.2.203", "switch"),
    ("CAM-SW-4TH", "Camera switch - 4th floor", "192.168.2.204", "switch"),
]

# title, severity, device, message, recommendation, status
ALERTS = [
    (
        "Suspicious network activity",
        "threat",
        "TSHSER003",
        "Simulated unusual outbound connection. Review network traffic and isolate if confirmed.",
        "Review traffic and isolate the device if confirmed.",
        "open",
    ),
    (
        "High CPU utilization",
        "warning",
        "TSHSER002",
        "Simulated CPU usage is above the warning threshold.",
        "Check resource usage on the host.",
        "resolved",
    ),
]

# ---------------------------------------------------------------------------
# SWITCHES  (from the spreadsheet tab "Switches")
# name must match a device in OTHER_DEVICES above.
# name, location, floor_order, kind, model, serial, access_ports, uplink_ports, note
# ICX 7150-48P = 48 PoE copper ports (1/1/1-48) + 2 copper uplinks (1/2/1-2) + 4 SFP+ (1/3/1-4).
# ICX 7250-24P = 24 PoE copper ports (1/1/1-24) + 8 SFP+ (1/2/1-8).
# ---------------------------------------------------------------------------
SWITCHES = [
    ("CORE-SWITCH", "Core / server room", 0, "core", "ICX 7250-24P", "DUI3838P05X", 24, 8,
     "Serial is assumed: it is the only model in the sheet's list that does not match a floor. Room is not stated in the sheet."),
    ("SW-B1", "Basement 1", 1, "floor", "ICX 7150-48P", "FEC3228Q06P", 48, 6, ""),
    ("CAM-SW-B1", "Basement 1", 1, "camera", "Not listed", "", 24, 2,
     "Camera switch. Model is not in the sheet: ports are an estimate until the first live poll reads the real ones."),
    ("SW-GROUND", "Ground floor", 2, "floor", "ICX 7150-48P", "FEC3228Q02D", 48, 6, ""),
    ("CAM-SW-GROUND", "Ground floor", 2, "camera", "Not listed", "", 24, 2,
     "Camera switch. Model is not in the sheet: ports are an estimate until the first live poll reads the real ones."),
    ("SW-1ST", "1st floor", 3, "floor", "ICX 7150-48P", "FEC3224N04K", 48, 6, ""),
    ("SW-2ND", "2nd floor", 4, "floor", "ICX 7150-48P", "FEC3228Q06H", 48, 6, ""),
    ("CAM-SW-2ND", "2nd floor", 4, "camera", "Not listed", "", 24, 2,
     "Camera switch. Model is not in the sheet: ports are an estimate until the first live poll reads the real ones."),
    ("SW-3RD", "3rd floor", 5, "floor", "ICX 7150-48P", "FEA3224Q016", 48, 6, ""),
    ("SW-4TH", "4th floor", 6, "floor", "ICX 7150-48P", "FEC3228Q06K", 48, 6, ""),
    ("CAM-SW-4TH", "4th floor", 6, "camera", "Not listed", "", 24, 2,
     "Camera switch. Model is not in the sheet: ports are an estimate until the first live poll reads the real ones."),
    ("SW-5TH", "5th floor", 7, "floor", "ICX 7150-48P", "FEC3228Q06N", 48, 6, ""),
    ("CAM-SW-CONTROL", "Control room", 8, "camera", "Not listed", "", 24, 2,
     "Camera switch. Model is not in the sheet: ports are an estimate until the first live poll reads the real ones."),
]

# Threats that can be met on switches and their ports.
# key, title, severity, how it is detected, what it means, what to do
SWITCH_THREATS = [
    ("switch_offline", "Switch unreachable", "threat", "poll",
     "The switch stopped answering. Everything plugged into it has lost the network.",
     "Check power and the uplink cable at the switch, then ping it from the core."),
    ("uplink_down", "Uplink down", "threat", "poll",
     "A link between switches went down. A whole floor can be cut off.",
     "Check the fibre or cable and both ends of the uplink first."),
    ("port_down", "Port down", "warning", "poll",
     "A port that was working lost its link: unplugged cable, powered-off device or a fault.",
     "Check the cable and the device on that port. Camera and access point ports matter most."),
    ("port_flapping", "Port flapping", "warning", "poll",
     "A port keeps going up and down. Usually a bad cable or port, sometimes someone tampering.",
     "Replace the cable, try another port, and look for a device being plugged in and out."),
    ("switch_reboot", "Unexpected reboot", "warning", "poll",
     "The switch restarted: power cut, crash, or someone restarted it.",
     "Check the audit log for who had access and look at the power supply."),
    ("snmp_down", "Switch not answering monitoring", "warning", "poll",
     "The switch answers ping but not SNMP, so port status cannot be read.",
     "Check the SNMP community and that SNMP is allowed from this server's IP."),
    ("mac_flood", "MAC flooding", "threat", "syslog",
     "A port is flooded with fake MAC addresses to overflow the switch table and sniff traffic.",
     "Shut the port, find the device, and enable port security on access ports."),
    ("rogue_dhcp", "Rogue DHCP server", "threat", "syslog",
     "An unauthorised device hands out IP addresses and can redirect traffic (man-in-the-middle).",
     "Find the port, disconnect the device and enable DHCP snooping."),
    ("arp_spoof", "ARP spoofing (man-in-the-middle)", "threat", "syslog",
     "A device pretends to be the gateway or a server to read or change traffic.",
     "Isolate the port at once and enable Dynamic ARP Inspection."),
    ("port_security", "Unknown device on a port", "threat", "syslog",
     "A device with an unapproved MAC address was plugged in (port security violation).",
     "Identify the device. Remove it or approve its MAC address."),
    ("stp_loop", "Network loop / STP change", "warning", "syslog",
     "A loop or a topology change was detected, which can slow or stop the whole floor.",
     "Find the cable that loops two ports and enable BPDU guard on access ports."),
    ("auth_fail", "Failed management logins", "threat", "syslog",
     "Repeated wrong logins to the switch (SSH or console): possible guessing attack.",
     "Check the source address, restrict management access to this server and rotate the password."),
    ("config_change", "Switch configuration changed", "warning", "syslog",
     "Someone changed the switch settings.",
     "Confirm the change was planned. Compare with the saved configuration."),
]
