#!/usr/bin/env python3
"""
Purge duplicate notes on Incidents in OpenCTI.

This script identifies notes with identical content attached to the same incident
and removes the duplicates, keeping only the oldest note per (content, incident) pair.

Usage:
    # Dry run (default) - just report duplicates
    python purge_duplicate_notes.py

    # Actually delete duplicates
    python purge_duplicate_notes.py --execute

    # Filter by connector/creator name
    python purge_duplicate_notes.py --creator "Recorded Future"

    # Filter by a specific incident ID
    python purge_duplicate_notes.py --incident-id <id>

Environment variables:
    OPENCTI_URL     - OpenCTI platform URL (e.g. https://opencti.example.com)
    OPENCTI_TOKEN   - API token with admin privileges
"""

import argparse
import hashlib
import logging
import os
import sys
import time
from collections import defaultdict

try:
    from pycti import OpenCTIApiClient
except ImportError:
    sys.exit(
        "Error: pycti is not installed. Install it with: pip install pycti"
    )

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# GraphQL fragments - lighter than the default pycti properties to go faster
# ---------------------------------------------------------------------------
NOTE_FIELDS = """
    id
    standard_id
    entity_type
    created
    created_at
    content
    authors
    attribute_abstract
    note_types
    confidence
    createdBy {
        id
        name
    }
    objects(all: true) {
        edges {
            node {
                ... on BasicObject {
                    id
                    entity_type
                }
            }
        }
    }
"""

NOTES_QUERY = """
query Notes($filters: FilterGroup, $first: Int, $after: ID, $orderBy: NotesOrdering, $orderMode: OrderingMode) {
    notes(filters: $filters, first: $first, after: $after, orderBy: $orderBy, orderMode: $orderMode) {
        edges {
            node {
                %s
            }
        }
        pageInfo {
            endCursor
            hasNextPage
            globalCount
        }
    }
}
""" % NOTE_FIELDS

DELETE_MUTATION = """
mutation StixDomainObjectEdit($id: ID!) {
    stixDomainObjectEdit(id: $id) {
        delete
    }
}
"""


def fetch_all_notes(client, filters=None, page_size=100):
    """Fetch all notes with pagination."""
    all_notes = []
    after = None
    has_next = True
    page = 0

    while has_next:
        page += 1
        result = client.query(
            NOTES_QUERY,
            {
                "filters": filters,
                "first": page_size,
                "after": after,
                "orderBy": "created_at",
                "orderMode": "asc",
            },
        )
        edges = result["data"]["notes"]["edges"]
        page_info = result["data"]["notes"]["pageInfo"]

        notes = [edge["node"] for edge in edges]
        all_notes.extend(notes)

        has_next = page_info["hasNextPage"]
        after = page_info["endCursor"]

        total = page_info.get("globalCount", "?")
        log.info(
            "Fetched page %d (%d notes so far / %s total)",
            page, len(all_notes), total,
        )

    return all_notes


def get_linked_incident_ids(note):
    """Extract incident IDs from a note's objects."""
    incident_ids = set()
    objects = note.get("objects") or {}
    edges = objects.get("edges") or []
    for edge in edges:
        node = edge.get("node", {})
        if node.get("entity_type") == "Incident":
            incident_ids.add(node["id"])
    return incident_ids


def content_hash(content):
    """Hash note content for grouping."""
    normalized = (content or "").strip()
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def find_duplicates(notes, per_incident=True):
    """
    Group notes by content (and optionally by incident) to find duplicates.

    Returns a dict: dedup_key -> list of notes (sorted by created_at asc).
    Only keys with >1 note are returned.
    """
    groups = defaultdict(list)

    for note in notes:
        c_hash = content_hash(note.get("content", ""))

        if per_incident:
            incident_ids = get_linked_incident_ids(note)
            if not incident_ids:
                # Note not linked to any incident - skip
                continue
            for inc_id in incident_ids:
                key = (c_hash, inc_id)
                groups[key].append(note)
        else:
            groups[c_hash].append(note)

    # Sort each group by created_at (oldest first) and filter to duplicates
    duplicates = {}
    for key, group in groups.items():
        # De-duplicate note list by id (a note can appear in multiple incident keys)
        seen_ids = set()
        unique = []
        for n in group:
            if n["id"] not in seen_ids:
                seen_ids.add(n["id"])
                unique.append(n)

        if len(unique) < 2:
            continue

        unique.sort(key=lambda n: n.get("created_at") or n.get("created") or "")
        duplicates[key] = unique

    return duplicates


def purge_duplicates(client, duplicates, execute=False):
    """Delete duplicate notes, keeping the oldest in each group."""
    total_to_delete = 0
    total_deleted = 0
    total_groups = len(duplicates)

    log.info("Found %d duplicate groups", total_groups)

    for i, (key, group) in enumerate(duplicates.items(), 1):
        keep = group[0]
        to_delete = group[1:]
        total_to_delete += len(to_delete)

        content_preview = (keep.get("content") or "")[:80].replace("\n", " ")
        if isinstance(key, tuple):
            log.info(
                "[Group %d/%d] Content: '%s...' | Incident: %s | "
                "Keeping: %s | Deleting %d duplicates",
                i, total_groups, content_preview, key[1],
                keep["id"], len(to_delete),
            )
        else:
            log.info(
                "[Group %d/%d] Content: '%s...' | "
                "Keeping: %s | Deleting %d duplicates",
                i, total_groups, content_preview,
                keep["id"], len(to_delete),
            )

        for note in to_delete:
            if execute:
                try:
                    client.query(DELETE_MUTATION, {"id": note["id"]})
                    total_deleted += 1
                    log.info("  Deleted note %s", note["id"])
                    # Throttle to avoid overloading the API
                    time.sleep(0.2)
                except Exception as e:
                    log.error("  Failed to delete note %s: %s", note["id"], e)
            else:
                log.info("  [DRY RUN] Would delete note %s (created: %s)",
                         note["id"], note.get("created_at"))

    return total_to_delete, total_deleted


def build_filters(args):
    """Build OpenCTI filter object from CLI args."""
    filter_list = []

    if args.creator:
        filter_list.append({
            "key": "createdBy",
            "values": [args.creator],
            "operator": "eq",
            "mode": "or",
        })

    if args.incident_id:
        filter_list.append({
            "key": "objects",
            "values": [args.incident_id],
            "operator": "eq",
            "mode": "or",
        })

    if not filter_list:
        return None

    return {
        "mode": "and",
        "filters": filter_list,
        "filterGroups": [],
    }


def main():
    parser = argparse.ArgumentParser(
        description="Purge duplicate notes on incidents in OpenCTI"
    )
    parser.add_argument(
        "--execute",
        action="store_true",
        help="Actually delete duplicates (default is dry-run)",
    )
    parser.add_argument(
        "--creator",
        type=str,
        default=None,
        help="Filter notes by creator/identity name (e.g. 'Recorded Future')",
    )
    parser.add_argument(
        "--incident-id",
        type=str,
        default=None,
        help="Only process notes linked to this specific incident ID",
    )
    parser.add_argument(
        "--global-dedup",
        action="store_true",
        help="Deduplicate by content only (not per-incident). "
             "Default is per-incident dedup.",
    )
    parser.add_argument(
        "--url",
        type=str,
        default=None,
        help="OpenCTI URL (overrides OPENCTI_URL env var)",
    )
    parser.add_argument(
        "--token",
        type=str,
        default=None,
        help="OpenCTI API token (overrides OPENCTI_TOKEN env var)",
    )
    parser.add_argument(
        "--page-size",
        type=int,
        default=100,
        help="Number of notes to fetch per page (default: 100)",
    )

    args = parser.parse_args()

    url = args.url or os.environ.get("OPENCTI_URL")
    token = args.token or os.environ.get("OPENCTI_TOKEN")

    if not url or not token:
        sys.exit(
            "Error: OPENCTI_URL and OPENCTI_TOKEN must be set "
            "(via env vars or --url / --token flags)"
        )

    if not args.execute:
        log.info("=== DRY RUN MODE (use --execute to actually delete) ===")

    # Connect
    client = OpenCTIApiClient(url, token)
    log.info("Connected to %s", url)

    # Build filters
    filters = build_filters(args)
    if filters:
        log.info("Using filters: %s", filters)

    # Fetch all notes
    log.info("Fetching notes...")
    notes = fetch_all_notes(client, filters=filters, page_size=args.page_size)
    log.info("Total notes fetched: %d", len(notes))

    if not notes:
        log.info("No notes found. Nothing to do.")
        return

    # Find duplicates
    per_incident = not args.global_dedup
    log.info(
        "Finding duplicates (%s)...",
        "per-incident" if per_incident else "global by content",
    )
    duplicates = find_duplicates(notes, per_incident=per_incident)

    if not duplicates:
        log.info("No duplicates found. Nothing to do.")
        return

    # Report summary
    total_dupes = sum(len(g) - 1 for g in duplicates.values())
    log.info(
        "Summary: %d duplicate groups, %d notes to delete",
        len(duplicates), total_dupes,
    )

    # Purge
    to_delete, deleted = purge_duplicates(client, duplicates, execute=args.execute)

    if args.execute:
        log.info("Done. Deleted %d / %d duplicate notes.", deleted, to_delete)
    else:
        log.info(
            "Dry run complete. %d duplicate notes would be deleted. "
            "Re-run with --execute to purge.",
            to_delete,
        )


if __name__ == "__main__":
    main()
