import { v4 as uuidv4 } from 'uuid';
import { createEntity } from '../../database/middleware';
import {
  type EntityOptions,
  fullEntitiesThroughRelationsToList,
  loadEntityThroughRelationsPaginated,
  pageEntitiesConnection,
  pageRegardingEntitiesConnection,
  storeLoadById,
} from '../../database/middleware-loader';
import type { AuthContext, AuthUser } from '../../types/user';
import type { ProcedureAddInput, QueryProceduresArgs } from '../../generated/graphql';
import { notify } from '../../database/redis';
import { BUS_TOPICS } from '../../config/conf';
import { ABSTRACT_STIX_CYBER_OBSERVABLE, ABSTRACT_STIX_DOMAIN_OBJECT, ENTITY_TYPE_IDENTITY } from '../../schema/general';
import type { DomainFindById } from '../../domain/domainTypes';
import { ENTITY_PROCESS } from '../../schema/stixCyberObservable';
import type { BasicStoreCommon, BasicStoreEntity } from '../../types/store';
import {
  type BasicStoreEntityProcedure,
  ENTITY_TYPE_PROCEDURE,
  RELATION_PROCEDURE_COMMAND,
  RELATION_PROCEDURE_OBSERVABLE,
  RELATION_PROCEDURE_SOURCE,
  STIX_TYPE_PROCEDURE,
} from './procedure-types';

export const findProcedureById: DomainFindById<BasicStoreEntityProcedure> = (context: AuthContext, user: AuthUser, procedureId: string) => {
  return storeLoadById(context, user, procedureId, ENTITY_TYPE_PROCEDURE);
};

export const findProcedurePaginated = (context: AuthContext, user: AuthUser, opts: QueryProceduresArgs) => {
  return pageEntitiesConnection<BasicStoreEntityProcedure>(context, user, [ENTITY_TYPE_PROCEDURE], opts);
};

// A procedure identity is never derived from its properties: each instance gets its own UUIDv4,
// unless a procedure STIX id is provided, which is kept so that re-imports upsert on it.
const procedureStandardId = (stixId: string | null | undefined) => {
  if (stixId && stixId.startsWith(`${STIX_TYPE_PROCEDURE}--`)) {
    return stixId;
  }
  return `${STIX_TYPE_PROCEDURE}--${uuidv4()}`;
};

export const addProcedure = async (context: AuthContext, user: AuthUser, input: ProcedureAddInput): Promise<BasicStoreEntityProcedure> => {
  // techniques are not an attribute of the procedure (implements-technique relationships)
  const { techniques: _techniques, ...procedureInput } = input;
  const procedureToCreate = { ...procedureInput, standard_id: procedureStandardId(input.stix_id) };
  const created = await createEntity(context, user, procedureToCreate, ENTITY_TYPE_PROCEDURE);
  return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].ADDED_TOPIC, created, user);
};

export const procedureObservablesPaginated = async <T extends BasicStoreEntity>(context: AuthContext, user: AuthUser, procedureId: string,
  args: EntityOptions<BasicStoreCommon>) => {
  return pageRegardingEntitiesConnection<T>(context, user, procedureId, RELATION_PROCEDURE_OBSERVABLE, ABSTRACT_STIX_CYBER_OBSERVABLE, false, args);
};

export const procedureCommand = async <T extends BasicStoreEntity>(context: AuthContext, user: AuthUser, procedureId: string) => {
  return loadEntityThroughRelationsPaginated<T>(context, user, procedureId, RELATION_PROCEDURE_COMMAND, ENTITY_PROCESS, false);
};

export const procedureSources = async <T extends BasicStoreEntity>(context: AuthContext, user: AuthUser, procedureId: string) => {
  return fullEntitiesThroughRelationsToList<T>(context, user, procedureId, RELATION_PROCEDURE_SOURCE, ENTITY_TYPE_IDENTITY);
};
