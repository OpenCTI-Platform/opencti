import type { Resolvers, TimelineEventSource, TimelinePrecision } from '../../generated/graphql';
import { BUS_TOPICS } from '../../config/conf';
import { subscribeToInstanceEvents } from '../../graphql/subscriptionWrapper';
import { loadCreators } from '../../database/members';
import { loadThroughDenormalized } from '../../resolvers/stix';
import { INPUT_CREATED_BY } from '../../schema/general';
import { ATTRIBUTE_TIMELINE_ANCHORS, ENTITY_TYPE_TIMELINE_EVENT, TIMELINE_ANCHOR_KEYS, TIMELINE_CONTAINER_TYPES } from './timeline-types';
import {
  addTimelineEvent,
  deleteTimelineEvent,
  editTimelineEvent,
  exportContainerTimeline,
  findContainerTimeline,
  findContainerTimelineSummary,
  findTimelineAnchors,
  findTimelineEvent,
  hideTimelineEvent,
  importTimelineExtension,
  listTimelineRules,
  pinTimelineEvent,
  regenerateTimeline,
  updateTimelineSettings,
} from './timeline-domain';

// Ordering values exposed on the lists of the timeline containers, resolved to the anchors attribute paths
const anchorOrdering = Object.fromEntries(TIMELINE_ANCHOR_KEYS.map((key) => [`timeline_${key}`, `${ATTRIBUTE_TIMELINE_ANCHORS}.${key}`]));

const timelineResolvers: Resolvers = {
  Query: {
    containerTimeline: (_, args, context) => findContainerTimeline(context, context.user, args),
    containerTimelineSummary: (_, { id }, context) => findContainerTimelineSummary(context, context.user, id),
    containerTimelineExport: (_, args, context) => exportContainerTimeline(context, context.user, args),
    timelineEvent: (_, { id }, context) => findTimelineEvent(context, context.user, id),
    timelineAnchors: (_, { containerId }, context) => findTimelineAnchors(context, context.user, containerId),
    timelineRules: () => listTimelineRules(),
  },
  TimelineEvent: {
    title: (event) => event.name,
    precision: (event) => event.time_precision as TimelinePrecision,
    source: (event) => event.event_source as TimelineEventSource,
    pinned: (event) => event.pinned ?? false,
    hidden: (event) => event.hidden ?? false,
    analyst_fields: (event) => event.analyst_fields ?? [],
    editable: (event) => event.event_source === 'manual',
    element: (event, _, context) => {
      if (!event.element_id) return null;
      return context.batch.idsBatchLoader.load({ id: event.element_id, type: event.element_type ?? undefined });
    },
    createdBy: (event, _, context) => loadThroughDenormalized(context, context.user, event, INPUT_CREATED_BY),
    objectMarking: (event, _, context) => context.batch.markingsBatchLoader.load(event),
    creators: (event, _, context) => loadCreators(context, context.user, event),
  },
  Mutation: {
    timelineEventAdd: (_, { input }, context) => addTimelineEvent(context, context.user, input),
    timelineEventEdit: (_, { id, input }, context) => editTimelineEvent(context, context.user, id, input),
    timelineEventDelete: (_, { id }, context) => deleteTimelineEvent(context, context.user, id),
    timelineEventPin: (_, { id, pinned }, context) => pinTimelineEvent(context, context.user, id, pinned),
    timelineEventHide: (_, { id, hidden }, context) => hideTimelineEvent(context, context.user, id, hidden),
    timelineSettingsUpdate: (_, { containerId, input }, context) => updateTimelineSettings(context, context.user, containerId, input),
    timelineRegenerate: (_, { containerId }, context) => regenerateTimeline(context, context.user, containerId),
    timelineImport: (_, { containerId, extension }, context) => importTimelineExtension(context, context.user, containerId, extension),
  },
  Subscription: {
    containerTimelineUpdated: {
      resolve: /* v8 ignore next */ (payload: any) => payload.instance,
      subscribe: /* v8 ignore next */ (_, { id }, context) => {
        const bus = BUS_TOPICS[ENTITY_TYPE_TIMELINE_EVENT];
        return subscribeToInstanceEvents(_, context, id, [bus.EDIT_TOPIC], { type: TIMELINE_CONTAINER_TYPES });
      },
    },
  },
  IncidentsOrdering: anchorOrdering,
  CaseIncidentsOrdering: anchorOrdering,
  CaseRfisOrdering: anchorOrdering,
  CaseRftsOrdering: anchorOrdering,
};

export default timelineResolvers;
