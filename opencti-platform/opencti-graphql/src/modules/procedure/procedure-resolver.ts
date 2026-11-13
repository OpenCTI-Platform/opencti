import type { Resolvers } from '../../generated/graphql';
import { addProcedure, findProcedureById, findProcedurePaginated, procedureCommand, procedureObservablesPaginated, procedureSources } from './procedure-domain';
import {
  stixDomainObjectAddRelation,
  stixDomainObjectCleanContext,
  stixDomainObjectDelete,
  stixDomainObjectDeleteRelation,
  stixDomainObjectEditContext,
  stixDomainObjectEditField,
} from '../../domain/stixDomainObject';
import { loadThroughDenormalized } from '../../resolvers/stix';
import { INPUT_KILLCHAIN } from '../../schema/general';
import { ENTITY_TYPE_PROCEDURE } from './procedure-types';

const procedureResolvers: Resolvers = {
  Query: {
    procedure: (_, { id }, context) => findProcedureById(context, context.user, id),
    procedures: (_, args, context) => findProcedurePaginated(context, context.user, args),
  },
  Procedure: {
    killChainPhases: (procedure, _, context) => loadThroughDenormalized(context, context.user, procedure, INPUT_KILLCHAIN, { sortBy: 'phase_name' }),
    procedureObservables: (procedure, args, context) => procedureObservablesPaginated<any>(context, context.user, procedure.id, args),
    procedureCommand: (procedure, _, context) => procedureCommand<any>(context, context.user, procedure.id),
    procedureSources: (procedure, _, context) => procedureSources<any>(context, context.user, procedure.id),
  },
  Mutation: {
    procedureAdd: (_, { input }, context) => {
      return addProcedure(context, context.user, input);
    },
    procedureDelete: (_, { id }, context) => {
      return stixDomainObjectDelete(context, context.user, id, ENTITY_TYPE_PROCEDURE);
    },
    procedureFieldPatch: (_, { id, input, commitMessage, references }, context) => {
      return stixDomainObjectEditField(context, context.user, id, input, { commitMessage, references });
    },
    procedureContextPatch: (_, { id, input }, context) => {
      return stixDomainObjectEditContext(context, context.user, id, input);
    },
    procedureContextClean: (_, { id }, context) => {
      return stixDomainObjectCleanContext(context, context.user, id);
    },
    procedureRelationAdd: (_, { id, input }, context) => {
      return stixDomainObjectAddRelation(context, context.user, id, input);
    },
    procedureRelationDelete: (_, { id, toId, relationship_type: relationshipType }, context) => {
      return stixDomainObjectDeleteRelation(context, context.user, id, toId, relationshipType);
    },
  },
};

export default procedureResolvers;
