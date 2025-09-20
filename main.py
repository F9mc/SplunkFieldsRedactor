#!/usr/bin/env python
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
from splunklib.searchcommands import (
    dispatch,
    StreamingCommand,
    Configuration,
    Option,
    validators,
)

import re

REDACT_CHAR = "X"


def redact(field: str) -> str:
    for pattern, func in patterns.items():
        if pattern.search(field):
            return func(field)


def redact_default(field: str, show: int = 2) -> str:
    if show <= len(field):
        return f"{field[:show]}{'X' * (len(field) - show)}"
    else:
        return REDACT_CHAR * len(field)


def redact_email(email: str) -> str:
    parts = email.split("@")
    return f"{redact_username(parts[0])}@{redact_domain(parts[1])}"


def redact_split(field: str, separator: str = ".", show: int = 2) -> str:
    parts = field.split(separator)
    redacted_parts = []
    for p in parts:
        if show <= len(p):
            redacted_parts.append(f"{p[:show]}{'X' * (len(p) - show)}")
        else:
            redacted_parts.append(REDACT_CHAR * len(p))

    return separator.join(redacted_parts)


def redact_username(username: str) -> str:
    return redact_split(username, ".", 2)


def redact_name(name: str) -> str:
    return redact_split(name, " ")


def redact_ipv4(ip: str) -> str:
    parts = ip.split(".")
    return f"{parts[0]}.{parts[1]}.XXX.{parts[3]}"


def redact_ipv6(ip: str) -> str:
    return redact_split(ip, ":", 3)


def redact_domain(domain: str) -> str:
    parts = domain.split(".")
    return f"{redact_split('.'.join(parts[:(len(parts) - 1)]), '.')}.{parts[len(parts) - 1:][0]}"


def redact_url(url: str) -> str:
    parts = url.split("/")
    if len(parts) > 3:
        return f"{''.join(parts[:1])}//{redact_domain(parts[2])}/{'/'.join(parts[3:])}"
    else:

        return f"{''.join(parts[:1])}//{redact_domain(parts[2])}"


def redact_phone(phone: str) -> str:
    for separator in [" ", ".", "-"]:
        if separator in phone:
            return redact_split(phone, separator, 1)


patterns = {
    re.compile(r"^[a-zA-Z]* [a-zA-Z]*$"): redact_name,
    re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"): redact_email,
    re.compile(
        r"^(?:25[0-5]|2[0-4]\d|[0-1]?\d{1,2})(?:\.(?:25[0-5]|2[0-4]\d|[0-1]?\d{1,2})){3}$"
    ): redact_ipv4,
    re.compile(
        r"([[:xdigit:]]{1,4}(?::[[:xdigit:]]{1,4}){7}|::|:(?::[[:xdigit:]]{1,4}){1,6}|[[:xdigit:]]{1,4}:(?::[[:xdigit:]]{1,4}){1,5}|(?:[[:xdigit:]]{1,4}:){2}(?::[[:xdigit:]]{1,4}){1,4}|(?:[[:xdigit:]]{1,4}:){3}(?::[[:xdigit:]]{1,4}){1,3}|(?:[[:xdigit:]]{1,4}:){4}(?::[[:xdigit:]]{1,4}){1,2}|(?:[[:xdigit:]]{1,4}:){5}:[[:xdigit:]]{1,4}|(?:[[:xdigit:]]{1,4}:){1,6}:)$"
    ): redact_ipv6,
    re.compile(r"^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$"): redact_domain,
    re.compile(r"^(https?|ftp)://[^\s/$.?#].[^\s]*$"): redact_url,
    re.compile(
        r"(?:([+]\d{1,4})[-.\s]?)?(?:[(](\d{1,3})[)][-.\s]?)?(\d{1,4})[-.\s]?(\d{1,4})[-.\s]?(\d{1,9})$"
    ): redact_phone,
    re.compile(r".*"): redact_default,
}


@Configuration()
class RedactorCommand(StreamingCommand):
    fields = Option()

    def stream(self, records):
        fields_list = [f.strip() for f in self.fields.split(",")]
        for record in records:
            for f in fields_list:
                if f in record:
                    try:
                        record[f] = redact(record[f])
                    except Exception:
                        record[f] = redact_default(record[f])
            yield record


dispatch(RedactorCommand, sys.argv, sys.stdin, sys.stdout, __name__)
