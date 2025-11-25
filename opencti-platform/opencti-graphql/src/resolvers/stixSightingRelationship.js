import { BUS_TOPICS } from '../config/conf';
import {
  addStixSightingRelationship,
  findStixSightingsPaginated,
  findById,
  stixSightingRelationshipAddRelation,
  stixSightingRelationshipAddRelations,
  stixSightingRelationshipCleanContext,
  stixSightingRelationshipDelete,
  stixSightingRelationshipDeleteRelation,
  stixSightingRelationshipEditContext,
  stixSightingRelationshipEditField,
  stixSightingRelationshipRemoveFromDraft,
  stixSightingRelationshipsNumber
} from '../domain/stixSightingRelationship';
import { fetchEditContext } from '../database/redis';
import { subscribeToInstanceEvents } from '../graphql/subscriptionWrapper';
import { distributionRelations, stixLoadByIdStringify, timeSeriesRelations } from '../database/middleware';
import { STIX_SIGHTING_RELATIONSHIP } from '../schema/stixSightingRelationship';
import { findById as findStatusById, getTypeStatuses } from '../domain/status';
import { addOrganizationRestriction, removeOrganizationRestriction } from '../domain/stix';
import { numberOfContainersForObject } from '../domain/container';
import { casesPaginated, containersPaginated, externalReferencesPaginated, notesPaginated, opinionsPaginated, reportsPaginated } from '../domain/stixCoreObject';
import { loadThroughDenormalized } from './stix';
import { INPUT_CREATED_BY, INPUT_GRANTED_REFS, INPUT_LABELS } from '../schema/general';
import { filterMembersWithUsersOrgs } from '../utils/access';

const stixSightingRelationshipResolvers = {
  Query: {
    stixSightingRelationship: (_, { id }, context) => findById(context, context.user, id),
    stixSightingRelationships: (_, args, context) => findStixSightingsPaginated(context, context.user, args),
    stixSightingRelationshipsTimeSeries: (_, args, context) => timeSeriesRelations(
      context,
      context.user,
      { ...args, relationship_type: [STIX_SIGHTING_RELATIONSHIP] },
    ),
    stixSightingRelationshipsDistribution: (_, args, context) => distributionRelations(
      context,
      context.user,
      { ...args, relationship_type: [STIX_SIGHTING_RELATIONSHIP] }
    ),
    stixSightingRelationshipsNumber: (_, args, context) => stixSightingRelationshipsNumber(context, context.user, args),
  },
  StixSightingRelationship: {
    from: (rel, _, context) => {
      // If relation is in a draft, we want to force the context to also be in the same draft
      const idLoadArgs = { id: rel.fromId, type: rel.fromType };
      return (rel.from ? rel.from : context.batch.idsBatchLoader.load(idLoadArgs));
    },
    to: (rel, _, context) => {
      // If relation is in a draft, we want to force the context to also be in the same draft
      const idLoadArgs = { id: rel.toId, type: rel.toType };
      return (rel.to ? rel.to : context.batch.idsBatchLoader.load(idLoadArgs));
    },
    // region batch fully loaded through rel de-normalization. Cant be ordered of filtered
    creators: async (rel, _, context) => {
      const creators = await context.batch.creatorsBatchLoader.load(rel.creator_id);
      if (!creators) {
        return [];
      }
      return filterMembersWithUsersOrgs(context, context.user, creators);
    },
    objectMarking: (stixCoreObject, _, context) => context.batch.markingsBatchLoader.load(stixCoreObject),
    createdBy: (rel, _, context) => loadThroughDenormalized(context, context.user, rel, INPUT_CREATED_BY),
    objectLabel: (rel, _, context) => loadThroughDenormalized(context, context.user, rel, INPUT_LABELS, { sortBy: 'value' }),
    objectOrganization: (rel, _, context) => loadThroughDenormalized(context, context.user, rel, INPUT_GRANTED_REFS, { sortBy: 'name' }),
    // endregion
    // region inner listing - cant be batch loaded
    externalReferences: (rel, args, context) => externalReferencesPaginated(context, context.user, rel.id, args),
    containers: (rel, args, context) => containersPaginated(context, context.user, rel.id, args),
    reports: (rel, args, context) => reportsPaginated(context, context.user, rel.id, args),
    cases: (rel, args, context) => casesPaginated(context, context.user, rel.id, args),
    notes: (rel, args, context) => notesPaginated(context, context.user, rel.id, args),
    opinions: (rel, args, context) => opinionsPaginated(context, context.user, rel.id, args),
    // endregion
    // Utils
    relationship_type: () => 'stix-sighting-relationship',
    toStix: (rel, args, context) => stixLoadByIdStringify(context, context.user, rel.id, args),
    editContext: (rel) => fetchEditContext(rel.id),
    status: (entity, _, context) => (entity.x_opencti_workflow_id ? findStatusById(context, context.user, entity.x_opencti_workflow_id) : null),
    workflowEnabled: async (entity, _, context) => {
      const statusesEdges = await getTypeStatuses(context, context.user, entity.entity_type);
      return statusesEdges.edges.length > 0;
    },
    // Figures
    containersNumber: (rel, args, context) => numberOfContainersForObject(context, context.user, { ...args, objectId: rel.id }),
  },
  Mutation: {
    stixSightingRelationshipEdit: (_, { id }, context) => ({
      delete: () => stixSightingRelationshipDelete(context, context.user, id),
      fieldPatch: ({ input, commitMessage, references }) => stixSightingRelationshipEditField(context, context.user, id, input, { commitMessage, references }),
      contextPatch: ({ input }) => stixSightingRelationshipEditContext(context, context.user, id, input),
      contextClean: () => stixSightingRelationshipCleanContext(context, context.user, id),
      relationAdd: ({ input }) => stixSightingRelationshipAddRelation(context, context.user, id, input),
      relationsAdd: ({ input, commitMessage, references }) => stixSightingRelationshipAddRelations(context, context.user, id, input, { commitMessage, references }),
      // eslint-disable-next-line max-len
      relationDelete: ({ toId, relationship_type: relationshipType, commitMessage, references }) => stixSightingRelationshipDeleteRelation(context, context.user, id, toId, relationshipType, { commitMessage, references }),
      restrictionOrganizationAdd: ({ organizationId, directContainerSharing }) => {
        return addOrganizationRestriction(context, context.user, id, organizationId, directContainerSharing);
      },
      restrictionOrganizationDelete: ({ organizationId, directContainerSharing }) => {
        return removeOrganizationRestriction(context, context.user, id, organizationId, directContainerSharing);
      },
      removeFromDraft: () => stixSightingRelationshipRemoveFromDraft(context, context.user, id),
    }),
    stixSightingRelationshipAdd: (_, { input }, context) => addStixSightingRelationship(context, context.user, input),
  },
  Subscription: {
    stixSightingRelationship: {
      resolve: /* v8 ignore next */ (payload) => payload.instance,
      subscribe: /* v8 ignore next */ (_, { id }, context) => {
        const preFn = () => stixSightingRelationshipEditContext(context, context.user, id);
        const cleanFn = () => stixSightingRelationshipCleanContext(context, context.user, id);
        const bus = BUS_TOPICS[STIX_SIGHTING_RELATIONSHIP];
        return subscribeToInstanceEvents(_, context, id, [bus.EDIT_TOPIC], { type: STIX_SIGHTING_RELATIONSHIP, preFn, cleanFn });
      },
    },
  },
};

export default stixSightingRelationshipResolvers;
