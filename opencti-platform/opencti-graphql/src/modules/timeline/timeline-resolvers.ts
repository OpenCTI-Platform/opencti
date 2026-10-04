import type { Resolvers, TimelineEventSource, TimelinePrecision } from '../../generated/graphql';
import type { AuthContext, AuthUser } from '../../types/user';
import type { BasicStoreEntity } from '../../types/store';
import { controlUserConfidenceAgainstElement } from '../../utils/confidence-level';
import { BUS_TOPICS } from '../../config/conf';
import { subscribeToInstanceEvents } from '../../graphql/subscriptionWrapper';
import { loadCreators } from '../../database/members';
import { loadThroughDenormalized } from '../../resolvers/stix';
import { ABSTRACT_STIX_DOMAIN_OBJECT, INPUT_CREATED_BY } from '../../schema/general';
import { isStixObject } from '../../schema/stixCoreObject';
import { isStixRelationship } from '../../schema/stixRelationship';
import { ATTRIBUTE_TIMELINE_ANCHORS, ENTITY_TYPE_TIMELINE_EVENT, TIMELINE_ANCHOR_KEYS, TIMELINE_CONTAINER_TYPES } from './timeline-types';
import {
  addTimelineEvent,
  canContributeToTimeline,
  deleteTimelineEvent,
  editTimelineEvent,
  exportContainerTimeline,
  exportContainerTimelineFile,
  findContainerTimeline,
  findContainerTimelineBounds,
  findContainerTimelineSummary,
  findTimelineAnchors,
  findTimelineEvent,
  hideTimelineEvent,
  importTimelineExtension,
  listTimelineRules,
  pinTimelineEvent,
  recordTimelineView,
  regenerateTimeline,
  timelineUpdateForUser,
  updateTimelineSettings,
  visibleTimelineUpdates,
} from './timeline-domain';

// Ordering values exposed on the lists of the timeline containers, resolved to the anchors attribute paths
const anchorOrdering = Object.fromEntries([...TIMELINE_ANCHOR_KEYS, 'computed_at', 'changed_at'].map((key) => [`timeline_${key}`, `${ATTRIBUTE_TIMELINE_ANCHORS}.${key}`]));

// Same rule as the mutations: the container can be updated outside drafts and the confidence of the event is reached
const canChangeTimelineEvent = async (context: AuthContext, event: { container_id: string }) => {
  // Incidents and cases share the Stix-Domain-Object parent type
  const container = await context.batch?.idsBatchLoader.load({ id: event.container_id, type: ABSTRACT_STIX_DOMAIN_OBJECT });
  return canContributeToTimeline(context, context.user as AuthUser, container)
    && controlUserConfidenceAgainstElement(context.user as AuthUser, event as unknown as BasicStoreEntity, true);
};

const timelineResolvers: Resolvers = {
  Query: {
    containerTimeline: (_, args, context) => findContainerTimeline(context, context.user, args),
    containerTimelineBounds: (_, args, context) => findContainerTimelineBounds(context, context.user, args),
    containerTimelineSummary: (_, { id, lanes, kinds }, context) => findContainerTimelineSummary(context, context.user, id, { lanes, kinds }),
    containerTimelineExport: (_, args, context) => exportContainerTimeline(context, context.user, args),
    containerTimelineExportFile: (_, args, context) => exportContainerTimelineFile(context, context.user, args),
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
    editable: async (event, _, context) => {
      if (event.event_source !== 'manual') return false;
      return canChangeTimelineEvent(context, event);
    },
    annotatable: (event, _, context) => canChangeTimelineEvent(context, event),
    element: (event, _, context) => {
      // Only STIX elements belong to the element union: internal soft-check sources (hunt or investigation
      // runs) keep their id and type on the event but are not resolved here
      if (!event.element_id || (event.element_type && !isStixObject(event.element_type) && !isStixRelationship(event.element_type))) {
        return null;
      }
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
    timelineViewed: (_, { containerId }, context) => recordTimelineView(context, context.user, containerId),
  },
  Subscription: {
    containerTimelineUpdated: {
      resolve: /* v8 ignore next */ (payload: any) => payload.instance,
      subscribe: /* v8 ignore next */ async (_, { id }, context) => {
        const bus = BUS_TOPICS[ENTITY_TYPE_TIMELINE_EVENT];
        const updates = await subscribeToInstanceEvents(_, context, id, [bus.EDIT_TOPIC], { type: TIMELINE_CONTAINER_TYPES });
        // Each subscriber only hears about the events it can read
        return visibleTimelineUpdates(updates[Symbol.asyncIterator](), (update) => timelineUpdateForUser(context, context.user, update));
      },
    },
  },
  IncidentsOrdering: anchorOrdering,
  CaseIncidentsOrdering: anchorOrdering,
  CaseRfisOrdering: anchorOrdering,
  CaseRftsOrdering: anchorOrdering,
};

export default timelineResolvers;
