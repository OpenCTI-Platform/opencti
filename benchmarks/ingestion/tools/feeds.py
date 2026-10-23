"""Feed-shaped bundles for the end-to-end benchmark, one list of bundles per feed, sent as its connector sends them.

The shapes follow what the AlienVault, Recorded Future and MISP connectors stored on the demo platform (October
2026): which objects, how many of each per pulse, risk list chunk or event, and which objects every bundle sends
again (authors, markings, malware, attack patterns, shared external references). Names and values carry the run
tag, so that a run counts what it stored.

    alienvault       one bundle per pulse: a report, ~30 indicators with their observables, ~13 `indicates` per
                     indicator towards malware, attack patterns and an intrusion set from shared pools
    recorded-future  one bundle per risk list chunk: 250 indicators with their observables and `indicates`, and the
                     malware, intrusion sets, attack patterns and vulnerabilities they point to, sent again each time
    misp             one bundle per event: a report with external references (some shared by many events),
                     ~30 indicators with observables, a long note, `related-to` between observables, galaxy entities
"""

import random
import uuid

from pycti.entities.opencti_attack_pattern import AttackPattern
from pycti.entities.opencti_identity import Identity
from pycti.entities.opencti_indicator import Indicator
from pycti.entities.opencti_intrusion_set import IntrusionSet
from pycti.entities.opencti_location import Location
from pycti.entities.opencti_malware import Malware
from pycti.entities.opencti_note import Note
from pycti.entities.opencti_report import Report
from pycti.entities.opencti_stix_core_relationship import StixCoreRelationship
from pycti.entities.opencti_vulnerability import Vulnerability

TLP_CLEAR = "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"
CREATED = "2026-01-01T00:00:00.000Z"
VALID_UNTIL = "2099-01-01T00:00:00.000Z"  # never expired: the expiration manager stays out of the measure


class Feed:
    def __init__(self, tag, seed):
        self.tag = tag
        self.random = random.Random(seed)

    def name(self, *parts):
        return "-".join(["ff", self.tag, *[str(p) for p in parts]])

    def author(self, name):
        return {
            "type": "identity",
            "spec_version": "2.1",
            "id": Identity.generate_id(self.name(name), "organization"),
            "name": self.name(name),
            "identity_class": "organization",
        }

    def refs(self, author, labels, external_references=None):
        refs = {
            "created_by_ref": author["id"],
            "object_marking_refs": [TLP_CLEAR],
            "labels": labels,
            "created": CREATED,
            "modified": CREATED,
        }
        if external_references:
            refs["external_references"] = external_references
        return refs

    def pool(self, kind, size):
        def make(i):
            name = self.name(kind, i)
            if kind == "malware":
                return {
                    "type": "malware",
                    "id": Malware.generate_id(name),
                    "name": name,
                    "is_family": True,
                }
            if kind == "intrusion-set":
                return {
                    "type": "intrusion-set",
                    "id": IntrusionSet.generate_id(name),
                    "name": name,
                }
            if kind == "attack-pattern":
                mitre = f"T{self.tag[-4:]}{i:04d}"
                return {
                    "type": "attack-pattern",
                    "id": AttackPattern.generate_id(name, mitre),
                    "name": name,
                    "x_mitre_id": mitre,
                }
            if kind == "vulnerability":
                cve = f"CVE-{self.tag[-4:]}-{i:05d}"
                return {
                    "type": "vulnerability",
                    "id": Vulnerability.generate_id(cve),
                    "name": cve,
                }
            if kind == "country":
                return {
                    "type": "location",
                    "id": Location.generate_id(name, "Country"),
                    "name": name,
                    "x_opencti_location_type": "Country",
                    "country": name,
                }
            raise ValueError(kind)

        return [{"spec_version": "2.1", **make(i)} for i in range(size)]

    def indicator_with_observable(self, author, labels, key, external_references=None):
        kind = self.random.choice(["domain-name", "url", "ipv4-addr", "file"])
        if kind == "domain-name":
            value = f"{key}.{self.tag}.example"
            observable = {"type": "domain-name", "value": value}
            pattern = f"[domain-name:value = '{value}']"
        elif kind == "url":
            value = f"https://{self.tag}.example/{key}"
            observable = {"type": "url", "value": value}
            pattern = f"[url:value = '{value}']"
        elif kind == "ipv4-addr":
            number = uuid.uuid5(uuid.NAMESPACE_URL, f"{self.tag}-{key}-ip").int % (
                250 * 250 * 250
            )
            value = f"10.{number // 62500 % 250}.{number // 250 % 250}.{number % 250}"
            observable = {"type": "ipv4-addr", "value": value}
            pattern = f"[ipv4-addr:value = '{value}']"
        else:
            value = uuid.uuid5(uuid.NAMESPACE_URL, f"{self.tag}-{key}").hex * 2
            observable = {"type": "file", "hashes": {"SHA-256": value}}
            pattern = f"[file:hashes.'SHA-256' = '{value}']"
        refs = self.refs(author, labels, external_references)
        observable = {
            **observable,
            "spec_version": "2.1",
            "id": f"{kind}--{uuid.uuid5(uuid.NAMESPACE_URL, f'{self.tag}-{key}-observable')}",
            **{
                k: v
                for k, v in refs.items()
                if k in ("created_by_ref", "object_marking_refs", "labels")
            },
        }
        indicator = {
            "type": "indicator",
            "spec_version": "2.1",
            "id": Indicator.generate_id(pattern),
            "name": self.name("indicator", key),
            "pattern": pattern,
            "pattern_type": "stix",
            "valid_from": CREATED,
            "valid_until": VALID_UNTIL,
            **refs,
        }
        return indicator, observable

    @staticmethod
    def rel(kind, source, target, refs):
        return {
            "type": "relationship",
            "spec_version": "2.1",
            "id": StixCoreRelationship.generate_id(kind, source["id"], target["id"]),
            "relationship_type": kind,
            "source_ref": source["id"],
            "target_ref": target["id"],
            **refs,
        }

    def report(self, name, author, labels, contained, external_references=None):
        return {
            "type": "report",
            "spec_version": "2.1",
            "id": Report.generate_id(self.name(name), CREATED),
            "name": self.name(name),
            "published": CREATED,
            "report_types": ["threat-report"],
            "object_refs": [o["id"] for o in contained],
            **self.refs(author, labels, external_references),
        }

    @staticmethod
    def bundle(objects):
        return {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": objects}


def alienvault(tag, n):
    feed = Feed(tag, 1)
    author = feed.author("alienvault")
    labels = [feed.name("tag", i) for i in range(40)]
    malware, techniques, sets, countries = (
        feed.pool("malware", 60),
        feed.pool("attack-pattern", 150),
        feed.pool("intrusion-set", 30),
        feed.pool("country", 20),
    )
    bundles = []
    for p in range(max(1, n // 520)):
        tags = feed.random.sample(labels, 4)
        refs = feed.refs(author, tags)
        pulse_malware, pulse_techniques = feed.random.sample(
            malware, 2
        ), feed.random.sample(techniques, 10)
        pulse_set, pulse_country = feed.random.choice(sets), feed.random.choice(
            countries
        )
        entities = [
            {**e, **refs}
            for e in [*pulse_malware, *pulse_techniques, pulse_set, pulse_country]
        ]
        indicators, observables, relationships = [], [], []
        for i in range(30):
            indicator, observable = feed.indicator_with_observable(
                author, tags, f"av{p}-{i}"
            )
            indicators.append(indicator)
            observables.append(observable)
            relationships.append(feed.rel("based-on", indicator, observable, refs))
            relationships += [
                feed.rel("indicates", indicator, target, refs)
                for target in [*pulse_malware, *pulse_techniques, pulse_set]
            ]
        relationships += [feed.rel("uses", pulse_set, m, refs) for m in pulse_malware]
        relationships += [
            feed.rel("uses", m, t, refs)
            for m in pulse_malware
            for t in pulse_techniques
        ]
        relationships.append(feed.rel("targets", pulse_set, pulse_country, refs))
        contained = [*entities, *indicators, *observables, *relationships]
        bundles.append(
            feed.bundle(
                [author, *contained, feed.report(f"pulse-{p}", author, tags, contained)]
            )
        )
    return bundles


def recorded_future(tag, n):
    feed = Feed(tag, 2)
    author = feed.author("recorded-future")
    rules = [feed.name("risk-rule", i) for i in range(25)]
    targets = [
        *feed.pool("malware", 150),
        *feed.pool("intrusion-set", 60),
        *feed.pool("attack-pattern", 120),
        *feed.pool("vulnerability", 70),
    ]
    bundles = []
    for c in range(max(1, n // 1100)):
        chunk_targets = feed.random.sample(targets, 120)
        objects = [author, *[{**t, **feed.refs(author, [])} for t in chunk_targets]]
        for i in range(250):
            tags = feed.random.sample(rules, 3)
            refs = feed.refs(author, tags)
            indicator, observable = feed.indicator_with_observable(
                author, tags, f"rf{c}-{i}"
            )
            objects += [
                indicator,
                observable,
                feed.rel("based-on", indicator, observable, refs),
            ]
            objects.append(
                feed.rel(
                    "indicates", indicator, feed.random.choice(chunk_targets), refs
                )
            )
            if i % 6 == 0:
                objects.append(
                    feed.rel(
                        "indicates", indicator, feed.random.choice(chunk_targets), refs
                    )
                )
        bundles.append(feed.bundle(objects))
    return bundles


def misp(tag, n):
    feed = Feed(tag, 3)
    author = feed.author("misp-org")
    tags_pool = [feed.name("misp-tag", i) for i in range(50)]
    analyses = [
        {
            "source_name": "External analysis",
            "url": f"https://analysis.example/{tag}/{i}",
        }
        for i in range(200)
    ]
    sets, malware, techniques = (
        feed.pool("intrusion-set", 40),
        feed.pool("malware", 60),
        feed.pool("attack-pattern", 120),
    )
    bundles = []
    for e in range(max(1, n // 136)):
        tags = feed.random.sample(tags_pool, 6)
        event_ref = {
            "source_name": "MISP",
            "url": f"https://misp.example/{tag}/events/view/{e}",
        }
        refs = feed.refs(author, tags, [event_ref])
        galaxy_set, galaxy_malware = feed.random.choice(sets), feed.random.choice(
            malware
        )
        entities = [
            {**g, **refs}
            for g in [galaxy_set, galaxy_malware, *feed.random.sample(techniques, 2)]
        ]
        indicators, observables, relationships = [], [], []
        for i in range(30):
            indicator, observable = feed.indicator_with_observable(
                author, tags, f"misp{e}-{i}", [event_ref]
            )
            indicators.append(indicator)
            observables.append(observable)
            relationships.append(feed.rel("based-on", indicator, observable, refs))
            relationships.append(feed.rel("indicates", indicator, galaxy_malware, refs))
        relationships += [
            feed.rel("related-to", observables[i], observables[i + 1], refs)
            for i in range(0, 20, 2)
        ]
        contained = [*entities, *indicators, *observables, *relationships]
        report = feed.report(
            f"event-{e}",
            author,
            tags,
            contained,
            [event_ref, *feed.random.sample(analyses, 3)],
        )
        content = f"Analysis of event {e} ({tag}). " + "Context paragraph. " * 120
        note = {
            "type": "note",
            "spec_version": "2.1",
            "id": Note.generate_id(CREATED, content),
            "abstract": feed.name("note", e),
            "content": content,
            "object_refs": [report["id"]],
            **refs,
        }
        bundles.append(feed.bundle([author, *contained, report, note]))
    return bundles


FEEDS = {"alienvault": alienvault, "recorded-future": recorded_future, "misp": misp}


def distinct_counts(bundles):
    """Distinct objects of each STIX type over the feed's bundles (what the platform should store)"""
    seen = {}
    for bundle in bundles:
        for o in bundle["objects"]:
            seen[o["id"]] = (
                o["type"] if o["type"] != "relationship" else o["relationship_type"]
            )
    counts = {}
    for kind in seen.values():
        counts[kind] = counts.get(kind, 0) + 1
    return counts
