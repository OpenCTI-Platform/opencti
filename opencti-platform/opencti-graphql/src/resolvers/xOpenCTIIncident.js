import {
  addXOpenCTIIncident,
  findAll,
  findById,
  xOpenCTIIncidentsTimeSeries,
  xOpenCTIIncidentsTimeSeriesByEntity,
} from '../domain/xOpenCTIIncident';
import {
  stixDomainObjectAddRelation,
  stixDomainObjectCleanContext,
  stixDomainObjectDelete,
  stixDomainObjectDeleteRelation,
  stixDomainObjectEditContext,
  stixDomainObjectEditField,
} from '../domain/stixDomainObject';
import { RELATION_CREATED_BY, RELATION_OBJECT_LABEL, RELATION_OBJECT_MARKING } from '../schema/stixMetaRelationship';
import { REL_INDEX_PREFIX } from '../schema/general';

const xOpenCTIIncidentResolvers = {
  Query: {
    xOpenCTIIncident: (_, { id }) => findById(id),
    xOpenCTIIncidents: (_, args) => findAll(args),
    xOpenCTIIncidentsTimeSeries: (_, args) => {
      if (args.objectId && args.objectId.length > 0) {
        return xOpenCTIIncidentsTimeSeriesByEntity(args);
      }
      return xOpenCTIIncidentsTimeSeries(args);
    },
  },
  XOpenCTIIncidentsFilter: {
    // eslint-disable-next-line no-undef
    createdBy: `${REL_INDEX_PREFIX}${RELATION_CREATED_BY}.internal_id`,
    markedBy: `${REL_INDEX_PREFIX}${RELATION_OBJECT_MARKING}.internal_id`,
    labelledBy: `${REL_INDEX_PREFIX}${RELATION_OBJECT_LABEL}.internal_id`,
  },
  Mutation: {
    xOpenCTIIncidentEdit: (_, { id }, { user }) => ({
      delete: () => stixDomainObjectDelete(user, id),
      fieldPatch: ({ input }) => stixDomainObjectEditField(user, id, input),
      contextPatch: ({ input }) => stixDomainObjectEditContext(user, id, input),
      contextClean: () => stixDomainObjectCleanContext(user, id),
      relationAdd: ({ input }) => stixDomainObjectAddRelation(user, id, input),
      relationDelete: ({ toId, relationship_type: relationshipType }) =>
        stixDomainObjectDeleteRelation(user, id, toId, relationshipType),
    }),
    xOpenCTIIncidentAdd: (_, { input }, { user }) => addXOpenCTIIncident(user, input),
  },
};

export default xOpenCTIIncidentResolvers;
