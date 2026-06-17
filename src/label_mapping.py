import re


LABEL_PATTERNS = {
    "BruteForce": [
        "failed password",
        "authentication failure",
        "invalid user",
        "ssh brute",
        "classified as bruteforce",
        "label=bruteforce",
        "patator",
    ],
    "WebAttack": [
        "sqlmap",
        "union select",
        "' or '1'='1",
        "or 1=1",
        "sqli",
        "sql injection",
        "classified as webattack",
        "label=webattack",
        "web attack",
        "xss",
    ],
    "DDoS": [
        "classified as ddos",
        "label=ddos",
        "ddos",
    ],
    "DoS": [
        "classified as dos",
        "label=dos",
        "dos hulk",
        "slowloris",
        "slowhttptest",
        "goldeneye",
    ],
    "PortScan": [
        "classified as portscan",
        "label=portscan",
        "portscan",
        "port scan",
    ],
    "Bot": [
        "classified as bot",
        "label=bot",
        "botnet",
    ],
    "Infiltration": [
        "classified as infiltration",
        "label=infiltration",
        "infiltration",
    ],
    "Heartbleed": [
        "classified as heartbleed",
        "label=heartbleed",
        "heartbleed",
    ],
    "Recon": [
        "nmap",
        "scan",
        "reconnaissance",
    ],
    "SuspiciousProcess": [
        "nc",
        "netcat",
        "bash -i",
        "reverse shell",
        "/bin/sh",
        "suspicious command",
    ],
}

ATTACK_KEYWORDS = [
    "failed password",
    "authentication failure",
    "invalid user",
    "classified as bruteforce",
    "label=bruteforce",
    "sqlmap",
    "union select",
    "or 1=1",
    "classified as webattack",
    "label=webattack",
    "ddos",
    "label=ddos",
    "label=dos",
    "portscan",
    "label=portscan",
    "label=bot",
    "label=infiltration",
    "label=heartbleed",
    "nmap",
    "scan",
    "nc",
    "netcat",
    "bash -i",
    "reverse shell",
    "/bin/sh",
    "chmod",
    "wget",
    "curl",
]


def normalize_text(*values: object) -> str:
    return " ".join(str(value).lower() for value in values if value is not None)


def contains_term(text: str, term: str) -> bool:
    if term in {"nc", "scan"}:
        return re.search(rf"\b{re.escape(term)}\b", text) is not None
    return term in text


def map_label(text: str) -> str:
    for label, patterns in LABEL_PATTERNS.items():
        if any(contains_term(text, pattern) for pattern in patterns):
            return label
    return "Benign"


def keyword_attack_score(text: str) -> int:
    return sum(1 for keyword in ATTACK_KEYWORDS if contains_term(text, keyword))
