import { addIncident, findAll, findById, incidentsTimeSeries, incidentsTimeSeriesByEntity } from '../domain/incident';
import {
  stixDomainObjectAddRelation,
  stixDomainObjectCleanContext,
  stixDomainObjectDelete,
  stixDomainObjectDeleteRelation,
  stixDomainObjectEditContext,
  stixDomainObjectEditField,
} from '../domain/stixDomainObject';
import { RELATION_CREATED_BY, RELATION_OBJECT_LABEL, RELATION_OBJECT_MARKING } from '../schema/stixMetaRelationship';
import { buildRefRelationKey } from '../schema/general';

const incidentResolvers = {
  Query: {
    incident: (_, { id }, { user }) => findById(user, id),
    incidents: (_, args, { user }) => findAll(user, args),
    incidentsTimeSeries: (_, args, { user }) => {
      if (args.objectId && args.objectId.length > 0) {
        return incidentsTimeSeriesByEntity(user, args);
      }
      return incidentsTimeSeries(user, args);
    },
  },
  IncidentsFilter: {
    createdBy: buildRefRelationKey(RELATION_CREATED_BY),
    markedBy: buildRefRelationKey(RELATION_OBJECT_MARKING),
    labelledBy: buildRefRelationKey(RELATION_OBJECT_LABEL),
  },
  Mutation: {
    incidentEdit: (_, { id }, { user }) => ({
      delete: () => stixDomainObjectDelete(user, id),
      fieldPatch: ({ input, commitMessage, references }) => stixDomainObjectEditField(user, id, input, { commitMessage, references }),
      contextPatch: ({ input }) => stixDomainObjectEditContext(user, id, input),
      contextClean: () => stixDomainObjectCleanContext(user, id),
      relationAdd: ({ input }) => stixDomainObjectAddRelation(user, id, input),
      relationDelete: ({ toId, relationship_type: relationshipType }) => stixDomainObjectDeleteRelation(user, id, toId, relationshipType),
    }),
    incidentAdd: (_, { input }, { user }) => addIncident(user, input),
  },
};

export default incidentResolvers;
