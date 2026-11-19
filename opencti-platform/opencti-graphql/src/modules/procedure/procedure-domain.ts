import { v4 as uuidv4 } from 'uuid';
import { createEntity, createRelation } from '../../database/middleware';
import {
  type EntityOptions,
  fullEntitiesThroughRelationsToList,
  loadEntityThroughRelationsPaginated,
  pageEntitiesConnection,
  pageRegardingEntitiesConnection,
  storeLoadById,
} from '../../database/middleware-loader';
import type { AuthContext, AuthUser } from '../../types/user';
import type { InputMaybe, ProcedureAddInput, QueryProceduresArgs } from '../../generated/graphql';
import { notify } from '../../database/redis';
import { BUS_TOPICS } from '../../config/conf';
import { ABSTRACT_STIX_CYBER_OBSERVABLE, ABSTRACT_STIX_DOMAIN_OBJECT, ENTITY_TYPE_IDENTITY } from '../../schema/general';
import type { DomainFindById } from '../../domain/domainTypes';
import { ENTITY_PROCESS } from '../../schema/stixCyberObservable';
import { ENTITY_TYPE_ATTACK_PATTERN } from '../../schema/stixDomainObject';
import { ENTITY_TYPE_KILL_CHAIN_PHASE } from '../../schema/stixMetaObject';
import { RELATION_HAS_OBSERVABLE, RELATION_IMPLEMENTS_TECHNIQUE } from '../../schema/stixCoreRelationship';
import { FunctionalError } from '../../config/errors';
import type { BasicStoreEntityKillChainPhase } from '../killChainPhase/killChainPhase-types';
import { computeProcedureFingerprint } from './procedure-fingerprint';
import type { BasicStoreCommon, BasicStoreEntity } from '../../types/store';
import { type BasicStoreEntityProcedure, ENTITY_TYPE_PROCEDURE, RELATION_PROCEDURE_COMMAND, RELATION_PROCEDURE_SOURCE, STIX_TYPE_PROCEDURE } from './procedure-types';

export const findProcedureById: DomainFindById<BasicStoreEntityProcedure> = (context: AuthContext, user: AuthUser, procedureId: string) => {
  return storeLoadById(context, user, procedureId, ENTITY_TYPE_PROCEDURE);
};

export const findProcedurePaginated = (context: AuthContext, user: AuthUser, opts: QueryProceduresArgs) => {
  return pageEntitiesConnection<BasicStoreEntityProcedure>(context, user, [ENTITY_TYPE_PROCEDURE], opts);
};

// A procedure identity is never derived from its properties: each instance gets its own UUIDv4,
// unless a procedure STIX id is provided, which is kept so that re-imports upsert on it.
const procedureStandardId = (stixId: string | null | undefined) => {
  const providedId = stixId?.toLowerCase();
  if (providedId && providedId.startsWith(`${STIX_TYPE_PROCEDURE}--`)) {
    return providedId;
  }
  return `${STIX_TYPE_PROCEDURE}--${uuidv4()}`;
};

const MITRE_ATTACK_KILL_CHAIN = 'mitre-attack';

const nonEmptyStrings = (values: InputMaybe<string>[] | null | undefined): string[] => (values ?? []).filter((v): v is string => !!v);

const loadTechniques = async (context: AuthContext, user: AuthUser, techniqueIds: string[]) => {
  const techniques: BasicStoreEntity[] = [];
  for (let i = 0; i < techniqueIds.length; i += 1) {
    const technique = await storeLoadById<BasicStoreEntity>(context, user, techniqueIds[i], ENTITY_TYPE_ATTACK_PATTERN);
    if (!technique) {
      throw FunctionalError('Cannot find the technique of the procedure', { id: techniqueIds[i] });
    }
    techniques.push(technique);
  }
  return techniques;
};

const loadObservables = async (context: AuthContext, user: AuthUser, observableIds: string[]) => {
  const observables: BasicStoreCommon[] = [];
  for (let i = 0; i < observableIds.length; i += 1) {
    const observable = await storeLoadById(context, user, observableIds[i], ABSTRACT_STIX_CYBER_OBSERVABLE);
    if (!observable) {
      throw FunctionalError('Cannot find the observable of the procedure', { id: observableIds[i] });
    }
    observables.push(observable);
  }
  return observables;
};

const loadMitrePhaseNames = async (context: AuthContext, user: AuthUser, killChainPhaseIds: string[]) => {
  const phaseNames: string[] = [];
  for (let i = 0; i < killChainPhaseIds.length; i += 1) {
    const phase = await storeLoadById<BasicStoreEntityKillChainPhase>(context, user, killChainPhaseIds[i], ENTITY_TYPE_KILL_CHAIN_PHASE);
    if (phase && phase.kill_chain_name === MITRE_ATTACK_KILL_CHAIN) {
      phaseNames.push(phase.phase_name);
    }
  }
  return phaseNames;
};

export const addProcedure = async (context: AuthContext, user: AuthUser, input: ProcedureAddInput): Promise<BasicStoreEntityProcedure> => {
  // techniques and observables are not attributes of the procedure (implements-technique and has-observable relationships)
  const { techniques: techniqueIds, procedureObservables: observableIds, ...procedureInput } = input;
  const techniques = await loadTechniques(context, user, nonEmptyStrings(techniqueIds));
  const observables = await loadObservables(context, user, nonEmptyStrings(observableIds));
  const procedureToCreate: Record<string, unknown> = { ...procedureInput, standard_id: procedureStandardId(input.stix_id) };
  // The fingerprint is set at creation only: an imported value is kept, edits never recompute it.
  if (!input.x_fingerprint) {
    const phaseNames = await loadMitrePhaseNames(context, user, nonEmptyStrings(input.killChainPhases));
    procedureToCreate.x_fingerprint = computeProcedureFingerprint(
      techniques.map((technique) => technique.standard_id),
      nonEmptyStrings(input.x_mitre_platforms),
      phaseNames,
    );
  }
  const created = await createEntity(context, user, procedureToCreate, ENTITY_TYPE_PROCEDURE);
  for (let i = 0; i < techniques.length; i += 1) {
    await createRelation(context, user, { fromId: created.id, toId: techniques[i].id, relationship_type: RELATION_IMPLEMENTS_TECHNIQUE });
  }
  for (let i = 0; i < observables.length; i += 1) {
    await createRelation(context, user, { fromId: created.id, toId: observables[i].id, relationship_type: RELATION_HAS_OBSERVABLE });
  }
  return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].ADDED_TOPIC, created, user);
};

export const procedureObservablesPaginated = async <T extends BasicStoreEntity>(context: AuthContext, user: AuthUser, procedureId: string,
  args: EntityOptions<BasicStoreCommon>) => {
  return pageRegardingEntitiesConnection<T>(context, user, procedureId, RELATION_HAS_OBSERVABLE, ABSTRACT_STIX_CYBER_OBSERVABLE, false, args);
};

export const procedureCommand = async <T extends BasicStoreEntity>(context: AuthContext, user: AuthUser, procedureId: string) => {
  return loadEntityThroughRelationsPaginated<T>(context, user, procedureId, RELATION_PROCEDURE_COMMAND, ENTITY_PROCESS, false);
};

export const procedureSources = async <T extends BasicStoreEntity>(context: AuthContext, user: AuthUser, procedureId: string) => {
  return fullEntitiesThroughRelationsToList<T>(context, user, procedureId, RELATION_PROCEDURE_SOURCE, ENTITY_TYPE_IDENTITY);
};
