import { graphql } from 'react-relay';
import type { PayloadError } from 'relay-runtime';
import { MESSAGING$ } from '../../../../relay/environment';

// Mutations return the fields they change so that Relay updates the events in place;
// adding, deleting, hiding and regenerating refetch the timeline.

/** Notify the payload errors of a completed mutation; true when the mutation was rejected. */
export const notifyTimelineMutationErrors = (errors: readonly PayloadError[] | null | undefined): boolean => {
  if (!errors || errors.length === 0) return false;
  MESSAGING$.notifyError(errors.map((error) => error.message).join('\n'));
  return true;
};

export const timelineEventAddMutation = graphql`
  mutation ContainerTimelineMutationsAddMutation($input: TimelineEventAddInput!) {
    timelineEventAdd(input: $input) {
      id
      title
      event_time
    }
  }
`;

export const timelineEventEditMutation = graphql`
  mutation ContainerTimelineMutationsEditMutation($id: ID!, $input: TimelineEventEditInput!) {
    timelineEventEdit(id: $id, input: $input) {
      id
      title
      description
      event_time
      event_end_time
      open_ended
      precision
      lane
      kind
      annotation
      confidence
      ordering_hint
      analyst_fields
      objectMarking {
        id
        definition_type
        definition
        x_opencti_order
        x_opencti_color
      }
    }
  }
`;

export const timelineEventDeleteMutation = graphql`
  mutation ContainerTimelineMutationsDeleteMutation($id: ID!) {
    timelineEventDelete(id: $id)
  }
`;

export const timelineEventPinMutation = graphql`
  mutation ContainerTimelineMutationsPinMutation($id: ID!, $pinned: Boolean!) {
    timelineEventPin(id: $id, pinned: $pinned) {
      id
      pinned
      analyst_fields
    }
  }
`;

export const timelineEventHideMutation = graphql`
  mutation ContainerTimelineMutationsHideMutation($id: ID!, $hidden: Boolean!) {
    timelineEventHide(id: $id, hidden: $hidden) {
      id
      hidden
      analyst_fields
    }
  }
`;

export const timelineSettingsUpdateMutation = graphql`
  mutation ContainerTimelineMutationsSettingsMutation($containerId: ID!, $input: TimelineSettingsInput!) {
    timelineSettingsUpdate(containerId: $containerId, input: $input) {
      id
      enabled_lanes
      default_grouping
      default_zoom_window
      hidden_kinds
    }
  }
`;

export const timelineRegenerateMutation = graphql`
  mutation ContainerTimelineMutationsRegenerateMutation($containerId: ID!) {
    timelineRegenerate(containerId: $containerId) {
      container_id
      derived_count
      created_count
      updated_count
      deleted_count
      truncated
    }
  }
`;

export const containerTimelineUpdatedSubscription = graphql`
  subscription ContainerTimelineMutationsUpdatedSubscription($id: ID!) {
    containerTimelineUpdated(id: $id) {
      container_id
      update_type
      changed_event_ids
      updated_at
    }
  }
`;

export const containerTimelineExportQuery = graphql`
  query ContainerTimelineMutationsExportQuery(
    $id: String!
    $format: TimelineExportFormat!
    $from: DateTime
    $to: DateTime
    $lanes: [TimelineLane!]
    $kinds: [TimelineEventKind!]
    $sources: [TimelineEventSource!]
    $search: String
    $includeHidden: Boolean
    $pinnedOnly: Boolean
    $labels: [TimelineExportLabelInput!]
    $contentMaxMarkings: [String!]
  ) {
    containerTimelineExport(
      id: $id
      format: $format
      from: $from
      to: $to
      lanes: $lanes
      kinds: $kinds
      sources: $sources
      search: $search
      includeHidden: $includeHidden
      pinnedOnly: $pinnedOnly
      labels: $labels
      contentMaxMarkings: $contentMaxMarkings
    )
  }
`;

export const containerTimelineExportFileQuery = graphql`
  query ContainerTimelineMutationsExportFileQuery(
    $id: String!
    $format: TimelineExportFormat!
    $labels: [TimelineExportLabelInput!]
    $contentMaxMarkings: [String!]
    $fileMarkings: [String!]
  ) {
    containerTimelineExportFile(
      id: $id
      format: $format
      labels: $labels
      contentMaxMarkings: $contentMaxMarkings
      fileMarkings: $fileMarkings
    ) {
      content
      file_markings {
        id
        definition
      }
    }
  }
`;

export const timelineViewedMutation = graphql`
  mutation ContainerTimelineMutationsViewedMutation($containerId: ID!) {
    timelineViewed(containerId: $containerId)
  }
`;
