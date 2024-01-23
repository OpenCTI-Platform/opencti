import { withFilter } from 'graphql-subscriptions';
import { BUS_TOPICS } from '../config/conf';
import {
  addStixSightingRelationship,
  findAll,
  findById,
  stixSightingRelationshipAddRelation,
  stixSightingRelationshipAddRelations,
  stixSightingRelationshipCleanContext,
  stixSightingRelationshipDelete,
  stixSightingRelationshipDeleteRelation,
  stixSightingRelationshipEditContext,
  stixSightingRelationshipEditField,
  stixSightingRelationshipsNumber
} from '../domain/stixSightingRelationship';
import { fetchEditContext, pubSubAsyncIterator } from '../database/redis';
import withCancel from '../graphql/subscriptionWrapper';
import { batchLoader, distributionRelations, stixLoadByIdStringify, timeSeriesRelations } from '../database/middleware';
import { STIX_SIGHTING_RELATIONSHIP } from '../schema/stixSightingRelationship';
import { elBatchIds } from '../database/engine';
import { findById as findStatusById, getTypeStatuses } from '../domain/status';
import { addOrganizationRestriction, removeOrganizationRestriction } from '../domain/stix';
import { batchCreators } from '../domain/user';
import { numberOfContainersForObject } from '../domain/container';
import {
  batchInternalRels,
  batchMarkingDefinitions,
  casesPaginated,
  containersPaginated,
  externalReferencesPaginated,
  notesPaginated,
  opinionsPaginated,
  reportsPaginated
} from '../domain/stixCoreObject';
import { RELATION_CREATED_BY, RELATION_GRANTED_TO, RELATION_OBJECT_LABEL } from '../schema/stixRefRelationship';

const loadByIdLoader = batchLoader(elBatchIds);
const relBatchLoader = batchLoader(batchInternalRels);
const markingDefinitionsLoader = batchLoader(batchMarkingDefinitions);
const creatorsLoader = batchLoader(batchCreators);

const stixSightingRelationshipResolvers = {
  Query: {
    stixSightingRelationship: (_, { id }, context) => findById(context, context.user, id),
    stixSightingRelationships: (_, args, context) => findAll(context, context.user, args),
    stixSightingRelationshipsTimeSeries: (_, args, context) => timeSeriesRelations(context, context.user, args),
    stixSightingRelationshipsDistribution: (_, args, context) => distributionRelations(
      context,
      context.user,
      { ...args, relationship_type: [STIX_SIGHTING_RELATIONSHIP] }
    ),
    stixSightingRelationshipsNumber: (_, args, context) => stixSightingRelationshipsNumber(context, context.user, args),
  },
  StixSightingRelationship: {
    from: (rel, _, context) => (rel.from ? rel.from : loadByIdLoader.load({ id: rel.fromId, type: rel.fromType }, context, context.user)),
    to: (rel, _, context) => (rel.to ? rel.to : loadByIdLoader.load({ id: rel.toId, type: rel.toType }, context, context.user)),
    // region batch fully loaded through rel de-normalization. Cant be ordered of filtered
    creators: (rel, _, context) => creatorsLoader.load(rel.creator_id, context, context.user),
    createdBy: (rel, _, context) => relBatchLoader.load({ element: rel, type: RELATION_CREATED_BY }, context, context.user),
    objectLabel: (stixCoreObject, _, context) => relBatchLoader.load({ element: stixCoreObject, type: RELATION_OBJECT_LABEL }, context, context.user),
    objectOrganization: (stixCoreObject, _, context) => relBatchLoader.load({ element: stixCoreObject, type: RELATION_GRANTED_TO }, context, context.user),
    objectMarking: (stixCoreObject, _, context) => markingDefinitionsLoader.load(stixCoreObject, context, context.user),
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
    toStix: (rel, _, context) => stixLoadByIdStringify(context, context.user, rel.id),
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
      restrictionOrganizationAdd: ({ organizationId }) => addOrganizationRestriction(context, context.user, id, organizationId),
      restrictionOrganizationDelete: ({ organizationId }) => removeOrganizationRestriction(context, context.user, id, organizationId),
    }),
    stixSightingRelationshipAdd: (_, { input }, context) => addStixSightingRelationship(context, context.user, input),
  },
  Subscription: {
    stixSightingRelationship: {
      resolve: /* v8 ignore next */ (payload) => payload.instance,
      subscribe: /* v8 ignore next */ (_, { id }, context) => {
        stixSightingRelationshipEditContext(context, context.user, id);
        const filtering = withFilter(
          () => pubSubAsyncIterator(BUS_TOPICS[STIX_SIGHTING_RELATIONSHIP].EDIT_TOPIC),
          (payload) => {
            if (!payload) return false; // When disconnect, an empty payload is dispatched.
            return payload.user.id !== context.user.id && payload.instance.id === id;
          }
        )(_, { id }, context);
        return withCancel(filtering, () => {
          stixSightingRelationshipCleanContext(context, context.user, id);
        });
      },
    },
  },
};

export default stixSightingRelationshipResolvers;
