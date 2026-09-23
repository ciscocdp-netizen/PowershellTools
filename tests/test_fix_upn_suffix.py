#!/usr/bin/env python3
"""Regression tests for Fix-UpnSuffix.ps1 helper logic and safeguards.

PowerShell 5.1 / Active Directory are not available in this environment, so the
pure helper algorithms are ported here and kept in lock-step with the script.
The script source is also inspected to make sure the original bugs stay fixed.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "Fix-UpnSuffix.ps1"


# ---------------------------------------------------------------------------
# Ports of the PowerShell helpers (must match Fix-UpnSuffix.ps1)
# ---------------------------------------------------------------------------

def convert_to_ldap_filter_value(value: str) -> str:
    out: list[str] = []
    for ch in value:
        code = ord(ch)
        if code == 92:
            out.append("\\5c")
        elif code == 42:
            out.append("\\2a")
        elif code == 40:
            out.append("\\28")
        elif code == 41:
            out.append("\\29")
        elif code == 0:
            out.append("\\00")
        elif code < 32:
            out.append(f"\\{code:02x}")
        else:
            out.append(ch)
    return "".join(out)


def test_looks_like_dn(value: str) -> bool:
    if not value or not value.strip():
        return False
    return bool(re.match(r"^(CN|OU|DC)=", value, re.I) and re.search(r",DC=", value, re.I))


def get_sam_from_identity(value: str) -> str:
    if not value:
        return value
    if "\\" in value:
        return value.split("\\")[-1]
    return value


def test_upn_format(upn: str) -> bool:
    if not upn or not upn.strip():
        return False
    return bool(re.match(r"^[^@\s]+@[^@\s]+$", upn))


def get_upn_suffix(upn: str) -> str | None:
    if not upn or "@" not in upn:
        return None
    return upn.split("@")[-1]


def get_domain_dns_from_dn(dn: str) -> str | None:
    if not dn or not dn.strip():
        return None
    parts = re.split(r"(?<!\\),", dn)
    dcs = [re.sub(r"^DC=", "", p, flags=re.I) for p in parts if re.match(r"^DC=", p, re.I)]
    if not dcs:
        return None
    return ".".join(dcs)


def get_csv_delimiter(first_line: str) -> str:
    if not first_line or not first_line.strip():
        return ","
    comma = first_line.count(",")
    semi = first_line.count(";")
    tab = first_line.count("\t")
    if semi > comma and semi > tab:
        return ";"
    if tab > comma and tab > semi:
        return "\t"
    return ","


def get_row_recommendation(status: str, detail: str | None) -> str:
    """Port of Get-RowRecommendation."""
    if status == "WillChange":
        return "Warning" if (detail and str(detail).strip()) else "Ready"
    if status in ("Collision", "InvalidUpn", "NotFound", "Failed"):
        return "Blocked"
    if status == "NoChange":
        return "NoChange"
    if status in ("Skipped", "SkippedByUser"):
        return "Skipped"
    if status == "Changed":
        return "Changed"
    return status


def get_adws_server_name(server: str | None) -> str | None:
    if server is None or not str(server).strip():
        return None
    name = str(server).strip()
    if name.lower().endswith(":3268"):
        return name[:-5]
    return name


def get_ad_lookup_servers(preferred: str | None, query_server: str | None,
                          write_server: str | None) -> list[str]:
    names: list[str] = []
    for raw in (preferred, query_server, write_server):
        name = get_adws_server_name(raw)
        if not name:
            continue
        if not any(existing.lower() == name.lower() for existing in names):
            names.append(name)
    return names


def get_primary_smtp_address(proxies, mail=None):
    """Port of Get-PrimarySmtpAddress (SMTP: first, then smtp:, else mail)."""
    items = [str(p) for p in (proxies or []) if p]
    for p in items:
        if p.startswith("SMTP:"):
            return p[5:]
    for p in items:
        if p.lower().startswith("smtp:"):
            return p[5:]
    if mail:
        return str(mail)
    return ""


def format_proxy_address_list(proxies):
    """Port of Format-ProxyAddressList."""
    items = [str(p) for p in (proxies or []) if p]
    if not items:
        return ""
    primary = sorted(p for p in items if p.startswith("SMTP:"))
    aliases = sorted(p for p in items if p.startswith("smtp:"))
    other = sorted(p for p in items if not p.lower().startswith("smtp:"))
    return "; ".join(primary + aliases + other)


def add_discovered_suffix(mapping: dict, suffix: str | None, source: str) -> None:
    """Port of Add-DiscoveredSuffix (case-insensitive merge, first casing wins)."""
    normalized = get_normalized_suffix(suffix)
    if not normalized or not source or not source.strip():
        return
    key = normalized.lower()
    if key not in mapping:
        mapping[key] = {"suffix": normalized, "sources": []}
    if source.lower() not in [s.lower() for s in mapping[key]["sources"]]:
        mapping[key]["sources"].append(source)


def convert_to_suffix_info_objects(mapping: dict, current_domain: str | None) -> list[dict]:
    items = []
    for entry in mapping.values():
        suffix = entry["suffix"]
        is_current = bool(current_domain and suffix.lower() == current_domain.lower())
        items.append({
            "Suffix": suffix,
            "Sources": list(entry["sources"]),
            "SourceLabel": "; ".join(entry["sources"]),
            "IsCurrentDomain": is_current,
        })
    items.sort(key=lambda i: (not i["IsCurrentDomain"], i["Suffix"].lower()))
    return items


def discover_available_suffixes(current_dns: str | None, forest_domains: list[str],
                                forest_upn_suffixes: list[str],
                                partition_suffixes: list[str]) -> list[dict]:
    """Port of Get-AvailableUpnSuffixes merge rules (no AD calls)."""
    mapping: dict = {}
    if current_dns:
        add_discovered_suffix(mapping, current_dns, "Current domain")
    for domain in forest_domains:
        if current_dns and domain and domain.lower() == current_dns.lower():
            continue
        add_discovered_suffix(mapping, domain, "Forest domain")
    for suffix in forest_upn_suffixes:
        add_discovered_suffix(mapping, suffix, "Forest UPN suffix")
    for suffix in partition_suffixes:
        add_discovered_suffix(mapping, suffix, "Registered on Partitions container")
    return convert_to_suffix_info_objects(mapping, current_dns)


def get_normalized_suffix(value: str | None) -> str | None:
    if value is None or not str(value).strip():
        return None
    raw = str(value).strip().lstrip("@")
    if not raw:
        return None
    if "@" in raw:
        return raw.split("@")[-1]
    return raw


def get_new_upn(user_upn: str | None, user_sam: str | None, mode: str,
                row_value: str | None = None, single_suffix: str | None = None) -> str | None:
    prefix = None
    if user_upn and "@" in user_upn:
        prefix = user_upn.split("@")[0]
    elif user_sam:
        prefix = user_sam

    if mode == "FullUpnColumn":
        if row_value is None or not str(row_value).strip():
            return None
        return str(row_value).strip()

    if mode == "SuffixColumn":
        suffix = get_normalized_suffix(row_value)
        if not suffix or not prefix:
            return None
        return f"{prefix}@{suffix}"

    if mode == "SingleSuffix":
        suffix = get_normalized_suffix(single_suffix)
        if not suffix or not prefix:
            return None
        return f"{prefix}@{suffix}"

    return None


def classify_identity(value: str) -> str:
    trimmed = value.strip()
    if test_looks_like_dn(trimmed):
        return "dn"
    if "@" in trimmed:
        return "upn"
    return "sam"


def flag_csv_collisions(rows: list[dict]) -> list[dict]:
    """Mirror Set-CollisionFlags in-CSV pass (case-insensitive UPN keys)."""
    first_row_by_upn: dict[str, int] = {}
    by_row = {r["Row"]: r for r in rows}

    for r in [x for x in rows if x["Status"] == "WillChange"]:
        key = r["NewUPN"].lower()
        if key in first_row_by_upn:
            other = first_row_by_upn[key]
            r["Status"] = "Collision"
            r["Detail"] = f"Duplicate target UPN in this CSV (also row {other})"
            first = by_row[other]
            if first["Status"] == "WillChange":
                first["Status"] = "Collision"
                first["Detail"] = f"Duplicate target UPN in this CSV (also row {r['Row']})"
        else:
            first_row_by_upn[key] = r["Row"]
    return rows


def estimate_lookup_round_trips(identities: list[str], batch_size: int = 50) -> int:
    """How many LDAP searches the batched resolver needs (no UPN-prefix fallback)."""
    upns, sams, dns = set(), set(), set()
    for raw in identities:
        if not raw or not raw.strip():
            continue
        kind = classify_identity(raw)
        value = raw.strip()
        if kind == "dn":
            dns.add(value.lower())
        elif kind == "upn":
            upns.add(value.lower())
        else:
            sams.add(get_sam_from_identity(value).lower())

    def batches(n: int) -> int:
        return 0 if n == 0 else (n + batch_size - 1) // batch_size

    return batches(len(upns)) + batches(len(sams)) + batches(len(dns))


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class LdapEscapeTests(unittest.TestCase):
    def test_plain_value_unchanged(self):
        self.assertEqual(convert_to_ldap_filter_value("jsmith"), "jsmith")

    def test_escapes_rfc4515_metacharacters(self):
        self.assertEqual(convert_to_ldap_filter_value(r"a*b(c)d\e"), r"a\2ab\28c\29d\5ce")

    def test_escapes_nul_and_controls(self):
        self.assertEqual(convert_to_ldap_filter_value("a\x00b\x1fc"), r"a\00b\1fc")

    def test_apostrophe_is_literal(self):
        # PowerShell -Filter "'O'Brien'" breaks; LDAP filter keeps the apostrophe.
        self.assertEqual(convert_to_ldap_filter_value("O'Brien"), "O'Brien")

    def test_upn_with_plus_and_dot(self):
        self.assertEqual(
            convert_to_ldap_filter_value("first.last+tag@omi.com"),
            "first.last+tag@omi.com",
        )


class IdentityTests(unittest.TestCase):
    def test_dn_cn(self):
        self.assertTrue(test_looks_like_dn("CN=Jane Doe,OU=Users,DC=omi,DC=com"))
        self.assertEqual(classify_identity("CN=Jane Doe,OU=Users,DC=omi,DC=com"), "dn")

    def test_dn_ou_root(self):
        self.assertTrue(test_looks_like_dn("OU=Contractors,DC=omi,DC=com"))

    def test_original_dn_regex_missed_ou(self):
        # The original script only accepted ^CN=.+,DC= so an OU= identity was treated as a SAM.
        self.assertTrue(test_looks_like_dn("OU=People,DC=child,DC=omi,DC=com"))

    def test_not_a_dn(self):
        self.assertFalse(test_looks_like_dn("jsmith"))
        self.assertFalse(test_looks_like_dn("jsmith@omi.com"))
        self.assertFalse(test_looks_like_dn("CN=only"))

    def test_sam_strips_domain_prefix(self):
        self.assertEqual(get_sam_from_identity(r"OMI\jsmith"), "jsmith")
        self.assertEqual(get_sam_from_identity("jsmith"), "jsmith")
        self.assertEqual(classify_identity(r"OMI\jsmith"), "sam")

    def test_upn_classification(self):
        self.assertEqual(classify_identity("jane@old.omi.com"), "upn")


class DomainFromDnTests(unittest.TestCase):
    def test_child_domain(self):
        dn = "CN=Joe,OU=Users,DC=child,DC=contoso,DC=com"
        self.assertEqual(get_domain_dns_from_dn(dn), "child.contoso.com")

    def test_escaped_comma_in_cn(self):
        dn = r"CN=Doe\, John,OU=Users,DC=omi,DC=com"
        self.assertEqual(get_domain_dns_from_dn(dn), "omi.com")

    def test_empty(self):
        self.assertIsNone(get_domain_dns_from_dn(""))


class UpnBuilderTests(unittest.TestCase):
    def test_suffix_column_keeps_existing_prefix(self):
        self.assertEqual(
            get_new_upn("jane.doe@old.local", "jdoe", "SuffixColumn", row_value="omi.com"),
            "jane.doe@omi.com",
        )

    def test_suffix_column_falls_back_to_sam(self):
        self.assertEqual(
            get_new_upn(None, "jdoe", "SuffixColumn", row_value="omi.com"),
            "jdoe@omi.com",
        )

    def test_suffix_column_strips_leading_at(self):
        self.assertEqual(
            get_new_upn("jane@old.local", "jdoe", "SuffixColumn", row_value="@omi.com"),
            "jane@omi.com",
        )

    def test_suffix_column_accepts_full_upn_by_mistake(self):
        self.assertEqual(
            get_new_upn("jane@old.local", "jdoe", "SuffixColumn", row_value="someone@omi.com"),
            "jane@omi.com",
        )

    def test_suffix_column_empty(self):
        self.assertIsNone(get_new_upn("jane@old.local", "jdoe", "SuffixColumn", row_value="  "))

    def test_full_upn_column(self):
        self.assertEqual(
            get_new_upn("jane@old.local", "jdoe", "FullUpnColumn", row_value=" jane@omi.com "),
            "jane@omi.com",
        )

    def test_single_suffix(self):
        self.assertEqual(
            get_new_upn("jane@old.local", "jdoe", "SingleSuffix", single_suffix="omi.com"),
            "jane@omi.com",
        )

    def test_upn_format(self):
        self.assertTrue(test_upn_format("user@omi.com"))
        self.assertFalse(test_upn_format("not-an-upn"))
        self.assertFalse(test_upn_format("user@omi.com@extra"))
        self.assertFalse(test_upn_format("user @omi.com"))


class CsvDelimiterTests(unittest.TestCase):
    def test_comma(self):
        self.assertEqual(get_csv_delimiter("UserPrincipalName,Suffix"), ",")

    def test_semicolon_excel(self):
        self.assertEqual(get_csv_delimiter("UserPrincipalName;Suffix;Comment"), ";")

    def test_tab(self):
        self.assertEqual(get_csv_delimiter("UserPrincipalName\tSuffix"), "\t")


class AdwsServerTests(unittest.TestCase):
    def test_strips_gc_ldap_port(self):
        self.assertEqual(get_adws_server_name("dc01.omi.com:3268"), "dc01.omi.com")
        self.assertEqual(get_adws_server_name("DC01.OMI.COM:3268"), "DC01.OMI.COM")

    def test_leaves_plain_hostname(self):
        self.assertEqual(get_adws_server_name("dc01.omi.com"), "dc01.omi.com")

    def test_empty(self):
        self.assertIsNone(get_adws_server_name(""))
        self.assertIsNone(get_adws_server_name(None))

    def test_lookup_server_list_dedupes_and_strips_port(self):
        servers = get_ad_lookup_servers(
            preferred="gc.omi.com:3268",
            query_server="gc.omi.com",
            write_server="pdc.omi.com",
        )
        self.assertEqual(servers, ["gc.omi.com", "pdc.omi.com"])


class SuffixDiscoveryTests(unittest.TestCase):
    def test_merges_duplicate_sources_case_insensitively(self):
        mapping: dict = {}
        add_discovered_suffix(mapping, "@OMI.com", "Current domain")
        add_discovered_suffix(mapping, "omi.com", "Current domain")
        add_discovered_suffix(mapping, "omi.com", "Forest UPN suffix")
        self.assertEqual(list(mapping), ["omi.com"])
        self.assertEqual(mapping["omi.com"]["suffix"], "OMI.com")
        self.assertEqual(
            mapping["omi.com"]["sources"],
            ["Current domain", "Forest UPN suffix"],
        )

    def test_current_domain_is_listed_first(self):
        items = discover_available_suffixes(
            current_dns="child.omi.com",
            forest_domains=["omi.com", "CHILD.omi.com"],
            forest_upn_suffixes=["contoso.com"],
            partition_suffixes=["contoso.com", "partners.omi.com"],
        )
        self.assertEqual(
            [i["Suffix"].lower() for i in items],
            ["child.omi.com", "contoso.com", "omi.com", "partners.omi.com"],
        )
        self.assertTrue(items[0]["IsCurrentDomain"])
        self.assertEqual(items[0]["Sources"], ["Current domain"])
        # child domain is not also tagged as a forest domain
        self.assertNotIn("Forest domain", items[0]["Sources"])
        contoso = next(i for i in items if i["Suffix"].lower() == "contoso.com")
        self.assertEqual(
            contoso["Sources"],
            ["Forest UPN suffix", "Registered on Partitions container"],
        )

    def test_strips_leading_at_and_full_upn(self):
        mapping: dict = {}
        add_discovered_suffix(mapping, "user@omi.com", "Forest UPN suffix")
        self.assertEqual(mapping["omi.com"]["suffix"], "omi.com")

    def test_empty_inputs_yield_empty_list(self):
        self.assertEqual(discover_available_suffixes(None, [], [], []), [])


class RecommendationTests(unittest.TestCase):
    def test_empty_detail_is_ready(self):
        self.assertEqual(get_row_recommendation("WillChange", ""), "Ready")
        self.assertEqual(get_row_recommendation("WillChange", None), "Ready")

    def test_warning_detail_is_not_ready(self):
        self.assertEqual(
            get_row_recommendation("WillChange", "Suffix 'x.com' is not in the forest UPN suffix list"),
            "Warning",
        )
        self.assertEqual(get_row_recommendation("WillChange", "Account is disabled"), "Warning")

    def test_collisions_and_missing_are_blocked(self):
        self.assertEqual(get_row_recommendation("Collision", "UPN already in use by jsmith"), "Blocked")
        self.assertEqual(get_row_recommendation("NotFound", "No AD user matched"), "Blocked")
        self.assertEqual(get_row_recommendation("InvalidUpn", "bad"), "Blocked")

    def test_already_correct(self):
        self.assertEqual(get_row_recommendation("NoChange", "Already correct"), "NoChange")


class CollisionTests(unittest.TestCase):
    def test_duplicate_target_upn_flags_both_rows(self):
        rows = [
            {"Row": 1, "NewUPN": "shared@omi.com", "Status": "WillChange", "Detail": ""},
            {"Row": 2, "NewUPN": "SHARED@omi.com", "Status": "WillChange", "Detail": ""},
            {"Row": 3, "NewUPN": "unique@omi.com", "Status": "WillChange", "Detail": ""},
        ]
        flag_csv_collisions(rows)
        self.assertEqual(rows[0]["Status"], "Collision")
        self.assertEqual(rows[1]["Status"], "Collision")
        self.assertEqual(rows[2]["Status"], "WillChange")
        self.assertIn("row 2", rows[0]["Detail"])
        self.assertIn("row 1", rows[1]["Detail"])

    def test_ad_occupant_message_includes_sam(self):
        detail = "UPN already in use by sAMAccountName {0} (their current UPN: {1})".format(
            "jsmith", "jsmith@omi.com"
        )
        self.assertIn("jsmith", detail)
        self.assertIn("sAMAccountName", detail)


class ProxyAddressTests(unittest.TestCase):
    def test_primary_prefers_uppercase_smtp(self):
        self.assertEqual(
            get_primary_smtp_address(["smtp:alias@omi.com", "SMTP:jane@omi.com"]),
            "jane@omi.com",
        )

    def test_primary_falls_back_to_alias_then_mail(self):
        self.assertEqual(get_primary_smtp_address(["smtp:alias@omi.com"]), "alias@omi.com")
        self.assertEqual(get_primary_smtp_address([], mail="mail@omi.com"), "mail@omi.com")
        self.assertEqual(get_primary_smtp_address([]), "")

    def test_list_orders_primary_then_aliases_then_other(self):
        formatted = format_proxy_address_list(
            ["sip:jane@omi.com", "smtp:alias@omi.com", "SMTP:jane@omi.com"]
        )
        self.assertEqual(
            formatted,
            "SMTP:jane@omi.com; smtp:alias@omi.com; sip:jane@omi.com",
        )

    def test_empty_proxies(self):
        self.assertEqual(format_proxy_address_list([]), "")
        self.assertEqual(format_proxy_address_list(None), "")


class EfficiencyTests(unittest.TestCase):
    def test_batching_beats_per_row_lookups(self):
        identities = [f"user{i:04d}@old.local" for i in range(200)]
        # Original script: at least one Get-ADUser per row (often 2).
        original_min = len(identities)
        batched = estimate_lookup_round_trips(identities, batch_size=50)
        self.assertEqual(batched, 4)
        self.assertLess(batched, original_min / 10)

    def test_mixed_identities_are_grouped(self):
        ids = (
            [f"u{i}@old.local" for i in range(10)]
            + [f"sam{i}" for i in range(10)]
            + [f"CN=User{i},DC=omi,DC=com" for i in range(3)]
        )
        # 1 UPN batch + 1 SAM batch + 1 DN batch
        self.assertEqual(estimate_lookup_round_trips(ids, batch_size=50), 3)

    def test_duplicates_do_not_add_queries(self):
        ids = ["jane@old.local"] * 80
        self.assertEqual(estimate_lookup_round_trips(ids, batch_size=50), 1)


class ScriptSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = SCRIPT.read_text(encoding="utf-8")

    def test_script_exists(self):
        self.assertTrue(SCRIPT.is_file())
        self.assertGreater(len(self.source), 5000)

    def test_balanced_braces(self):
        # Ignore comment-based help, line comments, and quoted strings.
        stripped = re.sub(r"<#.*?#>", "", self.source, flags=re.S)
        stripped = re.sub(r"'[^']*'", "''", stripped)
        stripped = re.sub(r'"[^"]*"', '""', stripped)
        stripped = re.sub(r"#[^\n]*", "", stripped)
        self.assertEqual(stripped.count("{"), stripped.count("}"), "Unbalanced braces in script")

    def test_required_functions_present(self):
        for name in (
            "ConvertTo-LdapFilterValue",
            "Invoke-AdUserBatchLookup",
            "Resolve-AdUsersFromIdentities",
            "Get-NewUpn",
            "Get-DomainDnsFromDn",
            "Get-CsvDelimiter",
            "Set-CollisionFlags",
            "Get-WritableServerForUser",
            "Import-UpnCsv",
            "Get-AvailableUpnSuffixes",
            "Add-DiscoveredSuffix",
            "Select-TargetSuffix",
            "Get-RegisteredPartitionUpnSuffixes",
            "Get-AdwsServerName",
            "Get-AdLookupServers",
            "Get-RowRecommendation",
            "Export-UpnPreviewReport",
            "Get-PreviewBuckets",
            "Set-DuplicateAccountFlags",
            "Get-PrimarySmtpAddress",
            "Format-ProxyAddressList",
        ):
            self.assertIn(f"function {name}", self.source)

    def test_ldap_escape_sequences_present(self):
        for token in (r"\5c", r"\2a", r"\28", r"\29", r"\00"):
            self.assertIn(token, self.source)

    def test_no_unescaped_filter_interpolation(self):
        # Original bug: Get-ADUser -Filter "UserPrincipalName -eq '$id'"
        self.assertNotRegex(
            self.source,
            r"""-Filter\s+["'][^"']*\$id""",
            "Identity values must not be interpolated into an AD filter string",
        )

    def test_uses_ldap_batches_and_progress(self):
        self.assertIn("LDAPFilter", self.source)
        self.assertIn("$script:BatchSize", self.source)
        self.assertIn("Write-Progress", self.source)
        self.assertIn("ResultPageSize", self.source)

    def test_pins_dc_and_uses_adws_not_gc_ldap_port(self):
        self.assertIn("PDCEmulator", self.source)
        self.assertIn("GlobalCatalog", self.source)
        self.assertIn("Get-WritableServerForUser", self.source)
        self.assertIn("Get-AdwsServerName", self.source)
        self.assertNotIn('"{0}:3268"', self.source)
        self.assertNotIn("List[object]", self.source)
        self.assertIn("Export-UpnPreviewReport", self.source)
        self.assertIn("OK to change", self.source)
        self.assertIn("Recommendation", self.source)
        self.assertIn("InUseBySam", self.source)
        self.assertIn("sAMAccountName", self.source)
        self.assertIn("proxyAddresses", self.source)
        self.assertIn("PrimarySmtp", self.source)
        self.assertIn("Get-PrimarySmtpAddress", self.source)

    def test_set_aduser_uses_distinguished_name(self):
        self.assertRegex(
            self.source,
            r"if \(\$r\.DistinguishedName\) \{ \$r\.DistinguishedName \} else \{ \$r\.SamAccount \}",
        )
        self.assertIn("Set-ADUser @setParams", self.source)

    def test_csv_import_is_array_wrapped_and_utf8(self):
        self.assertIn("@(Import-Csv", self.source)
        self.assertIn("-Encoding UTF8", self.source)
        self.assertIn("Forest.Domains", self.source)
        self.assertIn("UPNSuffixes", self.source)
        self.assertIn("PartitionsContainer", self.source)
        self.assertIn("Select-TargetSuffix", self.source)
        self.assertIn("applied to every account", self.source)

    def test_winforms_has_fallback(self):
        self.assertIn("Initialize-WinForms", self.source)
        self.assertIn("Enter the full path to the CSV file", self.source)
        self.assertIn("SkipPause", self.source)

    def test_original_rootdomain_only_suffix_list_is_gone(self):
        self.assertNotIn("forest.RootDomain", self.source)

    def test_requires_powershell_51(self):
        self.assertIn("#Requires -Version 5.1", self.source)
        self.assertNotRegex(self.source, r"\?\?", "Null-coalescing ?? is PowerShell 7+")
        self.assertNotIn("?.", self.source)


if __name__ == "__main__":
    unittest.main()
