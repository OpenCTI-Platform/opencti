import copy
import json
import os.path

import requests
from bs4 import BeautifulSoup

ALL_SCOs = "<all_SCOs>"

export_file_name = "stix_relationships-{}.json"
opencti_custom_file = "opencti_custom.json"
local_stix_docs_file = "./stix-v2.1-os.html"

headline = ["h1", "h2", "h3", "h4"]
simple_SOs = ["binary", "dictionary", "enum", "hex", "hashes"]

element_mapping = {0: "source", 1: "relationship", 2: "target"}

sco_list = [
    "alternate-data-stream-type",
    "archive-ext",
    "artifact",
    "autonomous-system",
    "directory",
    "domain-name",
    "email-addr",
    "email-message",
    "email-mime-part-type",
    "file",
    "http-request-ext",
    "icmp-ext",
    "ipv4-addr",
    "ipv6-addr",
    "mac-addr",
    "malware-analysis",
    "mutex",
    "network-traffic",
    "ntfs-ext",
    "pdf-ext",
    "pe-binary-ext",
    "process",
    "raster-image-ext",
    "socket-ext",
    "software",
    "tcp-ext",
    "unix-account-ext",
    "url",
    "user-account",
    "windows-pe-optional-header-type",
    "windows-pe-section-type",
    "windows-pebinary-ext",
    "windows-process-ext",
    "windows-registry-key",
    "windows-registry-value-type",
    "windows-service-ext",
    "x-opencti-cryptocurrency-wallet",
    "x-opencti-cryptographic-key",
    "x-opencti-hostname",
    "x-opencti-text",
    "x-opencti-user-agent",
    "x509-certificate",
    "x509-v3-extensions-type",
]

# translate those STIX entities
name_mapping = {
    "<All STIX Cyber-observable Objects>": [ALL_SCOs],
}

final_mapping = {ALL_SCOs: sco_list}

# those mapping were added manually, since automatic parsing for nested
# relations was not possible
hard_coded_mapping = {
    "file": {"contains": [ALL_SCOs]},
    "malware-analysis": {
        "sample": ["file", "network-traffic", "artifact"],
        "analysis-sco": [ALL_SCOs],
    },
    "malware": {"sample": ["file", "artifact"]},
    "windows-registry-key": {"values": ["windows-registry-value-type"]},
    "email-message": {"body-multipart": ["email-mime-part-type"]},
    "windows-pebinary-ext": {
        "sections": ["windows-pe-section-type"],
        "optional-header": ["windows-pe-optional-header-type"],
    },
    "ntfs-ext": {"alternate-data-streams": ["alternate-data-stream-type"]},
    "archive-ext": {"contains": ["file", "directory"]},
    "x509-certificate": {"x509-v3-extensions": ["x509-v3-extensions-type"]},
}

inverse_relationships = [
    "image",
    "process",
    "creator-user",
    "host-vm",
    "operating-system",
    "installed-software",
    "sample",
    "content",
    "src",
    "dst",
    "src-payload",
    "dst-payload",
    "from",
    "sender",
    "to",
    "cc",
    "bcc",
    "body-multipart",
    "raw-email",
    "body-raw",
    "alternate-data-streams",
    "optional-header",
    "sections",
    "message-body-data",
    "service-dll",
    "x509-v3-extensions"
]

# STIX documentation
stix_url = "https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html"


def is_identifier(content: list, so_list: list) -> bool:
    if "identifier" in content[1]:
        return True

    for so in so_list:
        if so in content[1]:
            return True

    return False


def parse_ref_properties(
    content: list, relationships: list, so_name: str, so_list: list[str]
) -> list:
    if len(content) == 0 or so_name in name_mapping.keys():
        return relationships

    # resolves-to and belongs-to is also a relationship
    if (
        "object_ref" in content[0]
        or "resolves_to" in content[0]
        or "external_references" in content[0]
    ):
        return relationships

    if not is_identifier(content, so_list):
        return relationships

    found_sos = []
    for so in so_list:
        if "MUST" in content[2]:
            if so in content[2].split("MUST")[1]:
                found_sos.append(so)

    relationship_name = content[0].split("_ref")[0].replace("_", "-")
    relationship_name = relationship_name.split(" ")[0]

    if len(found_sos) == 0:
        if (
            so_name in hard_coded_mapping
            and relationship_name in hard_coded_mapping[so_name]
        ):
            targets = hard_coded_mapping[so_name][relationship_name]
            found_sos += targets
            print(
                f"Using hardcoded approach for {so_name} -> {relationship_name}: {found_sos}"
            )
        else:
            print(
                f"Needs post processing ref? {so_name} -> {relationship_name} ({content})"
            )

    for so in found_sos:
        if relationship_name in inverse_relationships:
            print(f"Inversing {so_name} - {relationship_name} - {so}")
            relationships.append(
                {
                    element_mapping[0]: so,
                    element_mapping[1]: relationship_name,
                    element_mapping[2]: so_name,
                }
            )
        else:
            relationships.append(
                {
                    element_mapping[0]: so_name,
                    element_mapping[1]: relationship_name,
                    element_mapping[2]: so,
                }
            )

    return relationships


def parse_relationship(content: list, relationships: list) -> list:
    if content[0] == "—" or content[0] == "Source" or content[0] == "\x97":
        return relationships

    source = content[0]
    if source in name_mapping.keys():
        return relationships

    relationship = content[1]
    targets = content[2].split(",")
    for relat in relationship.split(","):
        for target in targets:
            target = target.strip()
            if target in name_mapping.keys():
                targets += name_mapping[target]
            else:
                relationships.append(
                    {
                        element_mapping[0]: source,
                        element_mapping[1]: relat.strip(),
                        element_mapping[2]: target,
                    }
                )

    return relationships


def get_so(items) -> list:
    so_list = []
    for item in items.findAll("p"):
        so_span = item.find(
            "span",
            {"style": "font-family:Consolas;color:#C7254E;background:#F9F2F4"},
            recursive=False,
            # string=re.compile(r"Type*")
        )
        if so_span and "Type Name" in item.text:
            so_name = item.text.split(": ")[1]
            if so_name in simple_SOs:
                continue

            so_list.append(so_name)
            print(f"SO found: {so_name}")

    return so_list


def parse_stix_docs():
    if os.path.isfile(local_stix_docs_file):
        with open(local_stix_docs_file, "r", encoding="ISO-8859-1") as f:
            contents = f.read()
    else:
        r = requests.get(stix_url, allow_redirects=True)
        contents = r.content
        with open(local_stix_docs_file, "wb") as file:
            file.write(contents)

    soup = BeautifulSoup(contents, "lxml")
    items = soup.body.div
    relationships = []

    so_list = get_so(items)

    for t in items.find_all("table"):
        parent_headline = set()
        so_name = ""
        for prev_tag in t.find_all_previous(["p"] + headline):
            if prev_tag.name in headline:
                parent_headline.add(prev_tag.name)

            if "Type Name" in prev_tag.text:
                so_name = prev_tag.text.split(": ")[1]
                break

            if len(parent_headline) >= 2:
                break

        # Not the table I'm looking for
        if so_name == "":
            continue

        # Relationship or property table
        table_type = ""
        info_beginning = False

        for tr in t.find_all("tr"):
            content = []
            for td in tr.find_all("td"):
                text = ""
                for p_elem in td.find_all("p"):
                    text += p_elem.text

                text = text.replace("\r", "").replace("\n", "").replace("  ", " ")

                if info_beginning:
                    content.append(text)

                # Detect Property Table
                if "Required Common Properties" in text:
                    table_type = "property"
                    break

                if "Property Name" in text:  # and table_type == "property":
                    table_type = "property"
                    info_beginning = True
                    break

                # Detect Relationship Table
                if "Relationship Type" in text:
                    info_beginning = True
                    table_type = "relationship"
                    break

                if "Reverse Relationships" in text:
                    info_beginning = False

            if table_type == "relationship" and (len(content) == 4):
                relationships = parse_relationship(content, relationships)
            elif table_type == "property":
                relationships = parse_ref_properties(
                    content, relationships, so_name, so_list
                )

        if table_type != "":
            print(f"SO: {so_name} Table type: {table_type}")

    unique_list = list(
        {
            (v[element_mapping[0]], v[element_mapping[1]], v[element_mapping[2]]): v
            for v in relationships
        }.values()
    )

    return unique_list


# overall = list of relationships
# opencti_additions = Custom OpenCTI STIX relationship additions
# resolve_mapping = Translate ALL_SCO entries to all SCO values
# suffix = suffix for result file
def export_json(
    overall: list,
    opencti_additions: dict[str, dict[str, list]] = None,
    resolve_mapping: bool = False,
    suffix: str = "backend",
):
    relation_list = copy.deepcopy(overall)
    if opencti_additions:
        for source, relationship in opencti_additions.items():
            for target, relations in relationship.items():
                for relation in relations:
                    if relation in inverse_relationships:
                        relation_list.append(
                            {
                                element_mapping[0]: target,
                                element_mapping[1]: relation,
                                element_mapping[2]: source,
                            }
                        )
                    else:
                        relation_list.append(
                            {
                                element_mapping[0]: source,
                                element_mapping[1]: relation,
                                element_mapping[2]: target,
                            }
                        )
    json_dict = {}

    for item in relation_list:
        source = item[element_mapping[0]]
        relationship = item[element_mapping[1]]
        single_target = item[element_mapping[2]]

        if resolve_mapping and single_target in final_mapping:
            targets = final_mapping[single_target]
        else:
            targets = [single_target]

        for target in targets:
            if source in json_dict:
                if target in json_dict[source]:
                    json_dict[source][target].append(relationship)
                else:
                    json_dict[source][target] = [relationship]
            else:
                json_dict[source] = {target: [relationship]}

    with open(export_file_name.format(suffix), "w", encoding="utf-8") as f:
        json.dump(json_dict, f, ensure_ascii=False, indent=4)


def read_opencti_custom_additions() -> dict:
    if os.path.isfile(opencti_custom_file):
        with open(opencti_custom_file, "r") as f:
            return json.loads(f.read())

    return {}


overall_list = parse_stix_docs()
opencti_additions = read_opencti_custom_additions()
export_json(overall_list, opencti_additions)
export_json(overall_list, opencti_additions, True, "frontend")
