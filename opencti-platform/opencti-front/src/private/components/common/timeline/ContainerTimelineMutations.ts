import { graphql } from 'react-relay';

// Mutations return the fields they change so that Relay updates the events in place;
// adding, deleting, hiding and regenerating refetch the timeline.

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
    $lanes: [TimelineLane!]
    $kinds: [TimelineEventKind!]
    $includeHidden: Boolean
    $labels: [TimelineExportLabelInput!]
  ) {
    containerTimelineExport(id: $id, format: $format, lanes: $lanes, kinds: $kinds, includeHidden: $includeHidden, labels: $labels)
  }
`;
