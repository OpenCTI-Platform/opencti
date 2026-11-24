import { v4 as uuidv4 } from 'uuid';
import { createEntity, createRelation, deleteElementById, updateAttribute } from '../../database/middleware';
import { lockResources } from '../../lock/master-lock';
import { SYSTEM_USER } from '../../utils/access';
import {
  type EntityOptions,
  fullEntitiesThroughRelationsToList,
  fullRelationsList,
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
import { RELATION_COMPONENT_OF, RELATION_HAS_OBSERVABLE, RELATION_IMPLEMENTS_TECHNIQUE } from '../../schema/stixCoreRelationship';
import { FunctionalError, MissingReferenceError } from '../../config/errors';
import type { BasicStoreEntityKillChainPhase } from '../killChainPhase/killChainPhase-types';
import { computeProcedureFingerprint } from './procedure-fingerprint';
import type { BasicStoreCommon, BasicStoreEntity, BasicStoreRelation } from '../../types/store';
import { ATTRIBUTE_COMPONENT_INDEX, ATTRIBUTE_COMPONENT_TYPE, checkComponentPosition, COMPONENT_TYPE_PRIMARY, FIRST_COMPONENT_PRIMARY_MESSAGE } from './procedure-components';
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
      // A missing reference, not a functional error: the import worker retries it once the observable is in.
      throw MissingReferenceError({ unresolvedIds: [observableIds[i]], doc_code: 'ELEMENT_NOT_FOUND' });
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

export type ProcedureComponent = {
  relationship_id: string;
  component_index: number;
  component_type: string;
  observable: BasicStoreCommon;
};

const listComponentRelationships = (context: AuthContext, user: AuthUser, procedureId: string) => {
  return fullRelationsList<BasicStoreRelation>(context, user, RELATION_COMPONENT_OF, { toId: procedureId });
};

// The procedure's components in sequence order. A component whose observable the user cannot see is left out.
export const procedureComponents = async (context: AuthContext, user: AuthUser, procedureId: string): Promise<ProcedureComponent[]> => {
  const relationships = await listComponentRelationships(context, user, procedureId);
  const components: ProcedureComponent[] = [];
  for (let i = 0; i < relationships.length; i += 1) {
    const relationship = relationships[i];
    const observable = await storeLoadById(context, user, relationship.fromId, ABSTRACT_STIX_CYBER_OBSERVABLE);
    if (observable) {
      components.push({
        relationship_id: relationship.id,
        component_index: relationship.component_index ?? 0,
        component_type: relationship.component_type ?? '',
        observable,
      });
    }
  }
  return components.sort((a, b) => a.component_index - b.component_index);
};

// Replaces the whole sequence: the index of each component is its position in the list.
// Everything is checked before the existing sequence is touched, and the existing relationships are updated
// in place (keeping their markings and history): new components are created, then removed ones deleted last.
export const setProcedureComponents = async (context: AuthContext, user: AuthUser, procedureId: string, components: { id: string; type: string }[]) => {
  const procedure = await storeLoadById<BasicStoreEntityProcedure>(context, user, procedureId, ENTITY_TYPE_PROCEDURE);
  if (!procedure) {
    throw FunctionalError('Cannot find the procedure', { id: procedureId });
  }
  if (components.length > 0 && components[0].type !== COMPONENT_TYPE_PRIMARY) {
    throw FunctionalError(FIRST_COMPONENT_PRIMARY_MESSAGE, { type: components[0].type });
  }
  const observableIds: string[] = [];
  for (let i = 0; i < components.length; i += 1) {
    checkComponentPosition(i, components[i].type);
    const observable = await storeLoadById(context, user, components[i].id, ABSTRACT_STIX_CYBER_OBSERVABLE);
    if (!observable) {
      throw FunctionalError('A component must be an observable.', { id: components[i].id });
    }
    if (observableIds.includes(observable.internal_id)) {
      throw FunctionalError('This observable is already in the sequence.', { id: components[i].id });
    }
    observableIds.push(observable.internal_id);
  }
  const lock = await lockResources([`procedure-components-${procedure.internal_id}`]);
  try {
    // A user may only rewrite a sequence they see whole: a component hidden by its relationship's or its observable's markings would be lost.
    const allRelationships = await listComponentRelationships(context, SYSTEM_USER, procedure.internal_id);
    const visibleRelationships = await listComponentRelationships(context, user, procedure.internal_id);
    const seenRelationships: BasicStoreRelation[] = [];
    for (let i = 0; i < visibleRelationships.length; i += 1) {
      if (await storeLoadById(context, user, visibleRelationships[i].fromId, ABSTRACT_STIX_CYBER_OBSERVABLE)) {
        seenRelationships.push(visibleRelationships[i]);
      }
    }
    if (seenRelationships.length !== allRelationships.length) {
      throw FunctionalError('This sequence holds components you cannot see.', { id: procedureId });
    }
    const existingByObservable = new Map(seenRelationships.map((relationship) => [relationship.fromId, relationship]));
    for (let i = 0; i < observableIds.length; i += 1) {
      const existing = existingByObservable.get(observableIds[i]);
      if (existing && (existing.component_index !== i || existing.component_type !== components[i].type)) {
        await updateAttribute(context, user, existing.id, RELATION_COMPONENT_OF, [
          { key: ATTRIBUTE_COMPONENT_INDEX, value: [i] },
          { key: ATTRIBUTE_COMPONENT_TYPE, value: [components[i].type] },
        ]);
      }
    }
    for (let i = 0; i < observableIds.length; i += 1) {
      if (!existingByObservable.has(observableIds[i])) {
        await createRelation(context, user, {
          fromId: observableIds[i],
          toId: procedure.internal_id,
          relationship_type: RELATION_COMPONENT_OF,
          component_index: i,
          component_type: components[i].type,
        });
      }
    }
    const removed = seenRelationships.filter((relationship) => !observableIds.includes(relationship.fromId));
    for (let i = 0; i < removed.length; i += 1) {
      await deleteElementById(context, user, removed[i].id, RELATION_COMPONENT_OF);
    }
  } finally {
    await lock.unlock();
  }
  return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].EDIT_TOPIC, procedure, user);
};
