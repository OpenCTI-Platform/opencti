# coding: utf-8

import json

TIMELINE_LANES = [
    "adversary",
    "evidence",
    "response",
    "knowledge",
    "detection",
    "custom",
]
TIMELINE_PRECISIONS = ["exact", "hour", "day", "approximate"]
TIMELINE_MILESTONE_KINDS = [
    "milestone",
    "containment",
    "eradication",
    "recovery",
    "notification",
]

# Fields of TimelineEventEditInput an update can carry
TIMELINE_EDITABLE_FIELDS = [
    "event_time",
    "event_end_time",
    "clear_event_end_time",
    "precision",
    "lane",
    "kind",
    "title",
    "description",
    "element_id",
    "confidence",
    "ordering_hint",
    "annotation",
    "createdBy",
    "objectMarking",
]


class TimelineEvent:
    """Main TimelineEvent class for OpenCTI

    Manages the events of incident and case timelines (Incident, Case-Incident,
    Case-Rfi, Case-Rft). Derived events are computed by the platform from the
    knowledge of the container; this class lets connectors and scripts push
    analyst milestones (manual events), annotate, pin or hide any event and
    read a timeline.

    :param opencti: instance of :py:class:`~pycti.api.opencti_api_client.OpenCTIApiClient`
    :type opencti: OpenCTIApiClient
    """

    def __init__(self, opencti):
        """Initialize the TimelineEvent instance.

        :param opencti: OpenCTI API client instance
        :type opencti: OpenCTIApiClient
        """
        self.opencti = opencti
        self.properties = """
            id
            standard_id
            entity_type
            parent_types
            container_id
            event_time
            event_end_time
            open_ended
            precision
            lane
            kind
            title
            description
            source
            rule_id
            element_id
            element_type
            pinned
            hidden
            annotation
            confidence
            ordering_hint
            external_id
            analyst_fields
            editable
            created_at
            updated_at
            createdBy {
                ... on Identity {
                    id
                    standard_id
                    entity_type
                    name
                }
            }
            objectMarking {
                id
                standard_id
                entity_type
                definition_type
                definition
                x_opencti_order
                x_opencti_color
            }
        """
        self.anchors_properties = """
            first_adversary_activity
            first_detection
            first_response
            containment
            closure
            computed_at
            changed_at
        """

    def list(self, **kwargs):
        """List the events of a container timeline, ordered by time.

        :param container_id: the id of the Incident or Case (required)
        :type container_id: str
        :param from_time: (optional) only events still running after this date
        :type from_time: str
        :param to_time: (optional) only events starting before this date
        :type to_time: str
        :param lanes: (optional) lanes to keep
        :type lanes: list
        :param kinds: (optional) kinds to keep
        :type kinds: list
        :param sources: (optional) sources to keep (derived, manual)
        :type sources: list
        :param markings: (optional) marking definition ids to keep
        :type markings: list
        :param search: (optional) full text search on title, description and annotation
        :type search: str
        :param include_hidden: (optional) include the hidden events (default: False)
        :type include_hidden: bool
        :param pinned_only: (optional) only the pinned events (default: False)
        :type pinned_only: bool
        :param first: (optional) page size (default: 200, max: 1000)
        :type first: int
        :param after: (optional) cursor of the page
        :type after: str
        :param getAll: (optional) iterate over every page (default: False)
        :type getAll: bool
        :param withPagination: (optional) return the pagination info (default: False)
        :type withPagination: bool
        :param customAttributes: (optional) attributes to return
        :type customAttributes: str
        :return: list of timeline events
        :rtype: list
        """
        container_id = kwargs.get("container_id", None)
        if container_id is None:
            self.opencti.app_logger.error(
                "[opencti_timeline_event] Missing parameters: container_id"
            )
            return None
        first = kwargs.get("first", 200)
        after = kwargs.get("after", None)
        get_all = kwargs.get("getAll", False)
        with_pagination = kwargs.get("withPagination", False)
        custom_attributes = kwargs.get("customAttributes", None)
        variables = {
            "id": container_id,
            "from": kwargs.get("from_time", None),
            "to": kwargs.get("to_time", None),
            "lanes": kwargs.get("lanes", None),
            "kinds": kwargs.get("kinds", None),
            "sources": kwargs.get("sources", None),
            "markings": kwargs.get("markings", None),
            "search": kwargs.get("search", None),
            "includeHidden": kwargs.get("include_hidden", False),
            "pinnedOnly": kwargs.get("pinned_only", False),
            "first": first,
            "after": after,
        }
        self.opencti.app_logger.info(
            "Listing timeline events",
            {"container_id": container_id, "lanes": json.dumps(variables["lanes"])},
        )
        query = (
            """
            query ContainerTimeline($id: String!, $from: DateTime, $to: DateTime, $lanes: [TimelineLane!], $kinds: [TimelineEventKind!], $sources: [TimelineEventSource!], $markings: [String!], $search: String, $includeHidden: Boolean, $pinnedOnly: Boolean, $first: Int, $after: ID) {
                containerTimeline(id: $id, from: $from, to: $to, lanes: $lanes, kinds: $kinds, sources: $sources, markings: $markings, search: $search, includeHidden: $includeHidden, pinnedOnly: $pinnedOnly, first: $first, after: $after) {
                    edges {
                        node {
                            """
            + (custom_attributes if custom_attributes is not None else self.properties)
            + """
                        }
                    }
                    pageInfo {
                        startCursor
                        endCursor
                        hasNextPage
                        hasPreviousPage
                        globalCount
                    }
                }
            }
        """
        )
        result = self.opencti.query(query, variables)
        if get_all:
            final_data = self.opencti.process_multiple(
                result["data"]["containerTimeline"]
            )
            while result["data"]["containerTimeline"]["pageInfo"]["hasNextPage"]:
                variables["after"] = result["data"]["containerTimeline"]["pageInfo"][
                    "endCursor"
                ]
                self.opencti.app_logger.debug(
                    "Listing timeline events", {"after": variables["after"]}
                )
                result = self.opencti.query(query, variables)
                final_data.extend(
                    self.opencti.process_multiple(result["data"]["containerTimeline"])
                )
            return final_data
        return self.opencti.process_multiple(
            result["data"]["containerTimeline"], with_pagination
        )

    def read(self, **kwargs):
        """Read a timeline event.

        :param id: the id of the timeline event (required)
        :type id: str
        :return: the timeline event or None
        :rtype: dict or None
        """
        id = kwargs.get("id", None)
        if id is None:
            self.opencti.app_logger.error(
                "[opencti_timeline_event] Missing parameters: id"
            )
            return None
        self.opencti.app_logger.info("Reading timeline event", {"id": id})
        query = (
            """
            query TimelineEvent($id: String!) {
                timelineEvent(id: $id) {
                    """
            + self.properties
            + """
                }
            }
        """
        )
        result = self.opencti.query(query, {"id": id})
        return self.opencti.process_multiple_fields(result["data"]["timelineEvent"])

    def create(self, **kwargs):
        """Add an analyst milestone (manual event) to a container timeline.

        Adding twice an event with the same ``external_id`` on the same container
        updates it, so connectors can push their milestones idempotently. An
        omitted field is not sent; a field passed as None is sent as null, so
        that adding the event again clears ``element_id``, ``confidence`` and
        ``createdBy``, which an omitted field leaves as stored.

        :param container_id: the id of the Incident or Case (required)
        :type container_id: str
        :param event_time: when the event happened (required)
        :type event_time: str
        :param title: the title of the event (required)
        :type title: str
        :param event_end_time: (optional) end of the event window
        :type event_end_time: str
        :param precision: (optional) exact, hour, day or approximate (default: exact)
        :type precision: str
        :param lane: (optional) adversary, evidence, response, knowledge, detection or custom (default: custom)
        :type lane: str
        :param kind: (optional) milestone, containment, eradication, recovery, notification or any event kind (default: milestone)
        :type kind: str
        :param description: (optional) description of the event
        :type description: str
        :param element_id: (optional) id of the object or relationship the event is about
        :type element_id: str
        :param confidence: (optional) confidence (0-100)
        :type confidence: int
        :param ordering_hint: (optional) order among the events sharing the same time
        :type ordering_hint: int
        :param annotation: (optional) analyst annotation
        :type annotation: str
        :param pinned: (optional) pin the event (default: False)
        :type pinned: bool
        :param createdBy: (optional) id of the author identity
        :type createdBy: str
        :param objectMarking: (optional) marking definition ids
        :type objectMarking: list
        :param external_id: (optional) idempotency key of the event in the source system
        :type external_id: str
        :return: the timeline event or None
        :rtype: dict or None
        """
        container_id = kwargs.get("container_id", None)
        event_time = kwargs.get("event_time", None)
        title = kwargs.get("title", None)
        if container_id is None or event_time is None or title is None:
            self.opencti.app_logger.error(
                "[opencti_timeline_event] Missing parameters: container_id, event_time and title"
            )
            return None
        lane = kwargs.get("lane", None)
        if lane is not None and lane not in TIMELINE_LANES:
            self.opencti.app_logger.error(
                "[opencti_timeline_event] Unknown lane", {"lane": lane}
            )
            return None
        precision = kwargs.get("precision", None)
        if precision is not None and precision not in TIMELINE_PRECISIONS:
            self.opencti.app_logger.error(
                "[opencti_timeline_event] Unknown precision", {"precision": precision}
            )
            return None
        self.opencti.app_logger.info(
            "Creating timeline event", {"container_id": container_id, "title": title}
        )
        timeline_input = {
            "container_id": container_id,
            "event_time": event_time,
            "title": title,
            "event_end_time": kwargs.get("event_end_time", None),
            "precision": precision,
            "lane": lane,
            "kind": kwargs.get("kind", None),
            "description": kwargs.get("description", None),
            "element_id": kwargs.get("element_id", None),
            "confidence": kwargs.get("confidence", None),
            "ordering_hint": kwargs.get("ordering_hint", None),
            "annotation": kwargs.get("annotation", None),
            "pinned": kwargs.get("pinned", None),
            "createdBy": kwargs.get("createdBy", None),
            "objectMarking": kwargs.get("objectMarking", None),
            "external_id": kwargs.get("external_id", None),
        }
        query = (
            """
            mutation TimelineEventAdd($input: TimelineEventAddInput!) {
                timelineEventAdd(input: $input) {
                    """
            + self.properties
            + """
                }
            }
        """
        )
        result = self.opencti.query(
            query,
            {
                "input": {
                    k: v
                    for k, v in timeline_input.items()
                    if v is not None or k in kwargs
                }
            },
        )
        return self.opencti.process_multiple_fields(result["data"]["timelineEventAdd"])

    def update(self, **kwargs):
        """Update a timeline event.

        Manual events accept every field; derived events only accept
        ``annotation`` and ``ordering_hint`` (use :py:meth:`pin` and
        :py:meth:`hide` for the flags).

        :param id: the id of the timeline event (required)
        :type id: str
        :param kwargs: the fields to change (see TIMELINE_EDITABLE_FIELDS); an
            omitted field is left unchanged. Passing None clears ``description``,
            ``annotation``, ``confidence``, ``ordering_hint``, ``element_id``
            and ``createdBy``; ``event_end_time=None`` is sent as
            ``clear_event_end_time`` and clears the end time. None is ignored
            (the value is kept) for the required or enumerated fields
            ``event_time``, ``title``, ``precision``, ``lane`` and ``kind``, and
            for ``objectMarking``. Markings are only ever added: the event
            keeps the markings it already carries and those of its element and
            of the container, so ``objectMarking`` adds markings and never
            removes one (``objectMarking=[]`` removes none)
        :return: the updated timeline event or None
        :rtype: dict or None
        """
        id = kwargs.get("id", None)
        if id is None:
            self.opencti.app_logger.error(
                "[opencti_timeline_event] Missing parameters: id"
            )
            return None
        edit_input = {
            field: kwargs[field]
            for field in TIMELINE_EDITABLE_FIELDS
            if field in kwargs
        }
        # The platform only clears the end time through its dedicated flag
        if "event_end_time" in edit_input and edit_input["event_end_time"] is None:
            del edit_input["event_end_time"]
            edit_input["clear_event_end_time"] = True
        if len(edit_input) == 0:
            self.opencti.app_logger.error(
                "[opencti_timeline_event] Nothing to update", {"id": id}
            )
            return None
        self.opencti.app_logger.info(
            "Updating timeline event", {"id": id, "fields": list(edit_input.keys())}
        )
        query = (
            """
            mutation TimelineEventEdit($id: ID!, $input: TimelineEventEditInput!) {
                timelineEventEdit(id: $id, input: $input) {
                    """
            + self.properties
            + """
                }
            }
        """
        )
        result = self.opencti.query(query, {"id": id, "input": edit_input})
        return self.opencti.process_multiple_fields(result["data"]["timelineEventEdit"])

    def delete(self, **kwargs):
        """Delete a manual timeline event (derived events can only be hidden).

        :param id: the id of the timeline event (required)
        :type id: str
        :return: the id of the deleted event or None
        :rtype: str or None
        """
        id = kwargs.get("id", None)
        if id is None:
            self.opencti.app_logger.error(
                "[opencti_timeline_event] Missing parameters: id"
            )
            return None
        self.opencti.app_logger.info("Deleting timeline event", {"id": id})
        query = """
            mutation TimelineEventDelete($id: ID!) {
                timelineEventDelete(id: $id)
            }
        """
        result = self.opencti.query(query, {"id": id})
        return result["data"]["timelineEventDelete"]

    def pin(self, **kwargs):
        """Pin or unpin a timeline event.

        :param id: the id of the timeline event (required)
        :type id: str
        :param pinned: (optional) True to pin, False to unpin (default: True)
        :type pinned: bool
        :return: the timeline event or None
        :rtype: dict or None
        """
        return self._set_flag("timelineEventPin", "pinned", **kwargs)

    def hide(self, **kwargs):
        """Hide or show a timeline event.

        :param id: the id of the timeline event (required)
        :type id: str
        :param hidden: (optional) True to hide, False to show (default: True)
        :type hidden: bool
        :return: the timeline event or None
        :rtype: dict or None
        """
        return self._set_flag("timelineEventHide", "hidden", **kwargs)

    def _set_flag(self, mutation, flag, **kwargs):
        id = kwargs.get("id", None)
        if id is None:
            self.opencti.app_logger.error(
                "[opencti_timeline_event] Missing parameters: id"
            )
            return None
        value = kwargs.get(flag, True)
        self.opencti.app_logger.info(
            "Updating timeline event flag", {"id": id, flag: value}
        )
        query = (
            """
            mutation TimelineEventFlag($id: ID!, $value: Boolean!) {
                """
            + mutation
            + "(id: $id, "
            + flag
            + """: $value) {
                    """
            + self.properties
            + """
                }
            }
        """
        )
        result = self.opencti.query(query, {"id": id, "value": value})
        return self.opencti.process_multiple_fields(result["data"][mutation])

    def anchors(self, **kwargs):
        """Read the anchors of a container timeline.

        :param container_id: the id of the Incident or Case (required)
        :type container_id: str
        :return: first_adversary_activity, first_detection, first_response, containment, closure,
            computed_at (last generation of the timeline from the knowledge of the container; a
            milestone, a pin or an annotation recomputes the anchors without moving it) and
            changed_at (last change of an anchor value)
        :rtype: dict or None
        """
        container_id = kwargs.get("container_id", None)
        if container_id is None:
            self.opencti.app_logger.error(
                "[opencti_timeline_event] Missing parameters: container_id"
            )
            return None
        query = (
            """
            query TimelineAnchors($containerId: String!) {
                timelineAnchors(containerId: $containerId) {
                    """
            + self.anchors_properties
            + """
                }
            }
        """
        )
        result = self.opencti.query(query, {"containerId": container_id})
        return result["data"]["timelineAnchors"]

    def regenerate(self, **kwargs):
        """Regenerate the derived events of a container timeline now.

        :param container_id: the id of the Incident or Case (required)
        :type container_id: str
        :return: the regeneration counters or None
        :rtype: dict or None
        """
        container_id = kwargs.get("container_id", None)
        if container_id is None:
            self.opencti.app_logger.error(
                "[opencti_timeline_event] Missing parameters: container_id"
            )
            return None
        self.opencti.app_logger.info(
            "Regenerating timeline", {"container_id": container_id}
        )
        query = """
            mutation TimelineRegenerate($containerId: ID!) {
                timelineRegenerate(containerId: $containerId) {
                    container_id
                    derived_count
                    manual_count
                    created_count
                    updated_count
                    deleted_count
                    truncated
                    duration_ms
                }
            }
        """
        result = self.opencti.query(query, {"containerId": container_id})
        return result["data"]["timelineRegenerate"]

    def import_extension(self, **kwargs):
        """Import the analyst contributions of a timeline STIX extension.

        Used when importing a container carrying the timeline extension: manual
        events are created (idempotent on their STIX id) and the annotations of
        derived events are applied once the platform derives them.

        :param container_id: the id of the Incident or Case (required)
        :type container_id: str
        :param extension: the content of the timeline extension (required)
        :type extension: dict
        :return: the regeneration counters or None
        :rtype: dict or None
        """
        container_id = kwargs.get("container_id", None)
        extension = kwargs.get("extension", None)
        if container_id is None or extension is None:
            self.opencti.app_logger.error(
                "[opencti_timeline_event] Missing parameters: container_id and extension"
            )
            return None
        self.opencti.app_logger.info(
            "Importing timeline contributions", {"container_id": container_id}
        )
        query = """
            mutation TimelineImport($containerId: ID!, $extension: String!) {
                timelineImport(containerId: $containerId, extension: $extension) {
                    container_id
                    derived_count
                    manual_count
                }
            }
        """
        result = self.opencti.query(
            query,
            {
                "containerId": container_id,
                "extension": (
                    extension if isinstance(extension, str) else json.dumps(extension)
                ),
            },
        )
        return result["data"]["timelineImport"]
