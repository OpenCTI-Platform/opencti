/*
Copyright (c) 2021-2025 Filigran SAS

This file is part of the OpenCTI Enterprise Edition ("EE") and is
licensed under the OpenCTI Enterprise Edition License (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

https://github.com/OpenCTI-Platform/opencti/blob/master/LICENSE

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*/

import { now } from 'moment';
import * as R from 'ramda';
import type { AuthContext, AuthUser } from '../../types/user';
import {
  type EntityOptions,
  internalLoadById,
  pageEntitiesConnection,
  pageRelationsConnection,
  type RelationOptions,
  storeLoadById,
  topRelationsList,
} from '../../database/middleware-loader';
import { type BasicStoreEntityPir, type BasicStoreRelationPir, ENTITY_TYPE_PIR, type PirExplanation, type StoreEntityPir } from './pir-types';
import {
  type EditInput,
  EditOperation,
  type FilterGroup,
  FilterMode,
  type MemberAccessInput,
  type PirAddInput,
  type PirFlagElementInput,
  type PirUnflagElementInput,
  type QueryPirLogsArgs,
  type QueryPirRelationshipsArgs,
  type QueryPirRelationshipsDistributionArgs,
  type QueryPirRelationshipsMultiTimeSeriesArgs,
} from '../../generated/graphql';
import { createEntity, deleteRelationsByFromAndTo, distributionRelations, timeSeriesRelations } from '../../database/middleware';
import { publishUserAction } from '../../listener/UserActionListener';
import { notify } from '../../database/redis';
import { BUS_TOPICS, logApp } from '../../config/conf';
import { deleteInternalObject, editInternalObject } from '../../domain/internalObject';
import type { BasicStoreCommon, BasicStoreObject } from '../../types/store';
import { RELATION_OBJECT } from '../../schema/stixRefRelationship';
import { createPirRelation, serializePir, updatePirExplanations } from './pir-utils';
import { getPirWithAccessCheck } from './pir-checkPirAccess';
import { ForbiddenAccess, FunctionalError, LockTimeoutError, TYPE_LOCK_ERROR } from '../../config/errors';
import { ABSTRACT_STIX_REF_RELATIONSHIP, ENTITY_TYPE_CONTAINER } from '../../schema/general';
import { addDynamicFromAndToToFilters, addFilter, extractFilterKeyValues, isFilterGroupNotEmpty } from '../../utils/filtering/filtering-utils';
import {
  INSTANCE_DYNAMIC_REGARDING_OF,
  INSTANCE_REGARDING_OF,
  OBJECT_CONTAINS_FILTER,
  RELATION_TO_FILTER,
  RELATION_TYPE_SUBFILTER,
} from '../../utils/filtering/filtering-constants';
import { checkEnterpriseEdition } from '../../enterprise-edition/ee';
import { editAuthorizedMembers } from '../../utils/authorizedMembers';
import { isBypassUser, MEMBER_ACCESS_ALL, MEMBER_ACCESS_RIGHT_ADMIN, MEMBER_ACCESS_RIGHT_VIEW } from '../../utils/access';
import { RELATION_IN_PIR } from '../../schema/internalRelationship';
import { READ_INDEX_HISTORY } from '../../database/utils';
import { ENTITY_TYPE_HISTORY, ENTITY_TYPE_PIR_HISTORY } from '../../schema/internalObject';
import { elPaginate, type PaginateOpts } from '../../database/engine';
import { registerConnectorQueues, unregisterConnector } from '../../database/rabbitmq';
import { lockResources } from '../../lock/master-lock';
import type { LogConnection } from '../../types/log';

export const findById = async (context: AuthContext, user: AuthUser, id: string) => {
  await checkEnterpriseEdition(context);
  return storeLoadById<BasicStoreEntityPir>(context, user, id, ENTITY_TYPE_PIR);
};

export const findPirPaginated = async (context: AuthContext, user: AuthUser, opts?: EntityOptions<BasicStoreEntityPir>) => {
  await checkEnterpriseEdition(context);
  return pageEntitiesConnection<BasicStoreEntityPir>(context, user, [ENTITY_TYPE_PIR], opts);
};

export const findPirRelationPaginated = async (
  context: AuthContext,
  user: AuthUser,
  opts: QueryPirRelationshipsArgs,
) => {
  const { pirId } = opts;
  if (!pirId) {
    throw FunctionalError('You should provide a Pir ID since in-pir relationships can only be fetch for a given PIR.', { pirId });
  }
  await getPirWithAccessCheck(context, user, pirId);
  return pageRelationsConnection<BasicStoreRelationPir>(context, user, RELATION_IN_PIR, { ...R.dissoc('pirId', opts), toId: [pirId] } as RelationOptions<BasicStoreRelationPir>);
};

export const pirRelationshipsDistribution = async (
  context: AuthContext,
  user: AuthUser,
  opts: QueryPirRelationshipsDistributionArgs,
) => {
  // check for PIR
  const relationship_type = [RELATION_IN_PIR];
  const { pirId } = opts;
  if (!pirId) {
    throw FunctionalError('You should provide exactly a Pir ID since in-pir relationships distribution can only be fetch for a given PIR.', { pirId });
  }
  await getPirWithAccessCheck(context, user, pirId);
  // build args
  const args = { ...R.dissoc('pirId', opts), relationship_type, toId: [pirId] };
  const filters = addDynamicFromAndToToFilters(args);
  const fullArgs = { ...args, filters };
  return distributionRelations(context, user, fullArgs as unknown as any) as unknown as any;
};

export const pirRelationshipsMultiTimeSeries = async (
  context: AuthContext,
  user: AuthUser,
  opts: QueryPirRelationshipsMultiTimeSeriesArgs,
) => {
  const relationship_type = [RELATION_IN_PIR];
  if (!opts.timeSeriesParameters) {
    return [];
  }
  return Promise.all(opts.timeSeriesParameters.map(async (timeSeriesParameter) => {
    const { pirId } = timeSeriesParameter;
    await getPirWithAccessCheck(context, user, pirId);

    const filters = addDynamicFromAndToToFilters(timeSeriesParameter);
    const fullArgs = { ...R.dissoc('pirId', timeSeriesParameter), filters };
    return { data: await timeSeriesRelations(context, user, { ...opts, relationship_type, toId: [pirId], ...fullArgs } as unknown as any) };
  }));
};

export const findPirHistory = async (context: AuthContext, user: AuthUser, args: QueryPirLogsArgs) => {
  const { pirId } = args;
  await getPirWithAccessCheck(context, user, pirId);
  const filters = addFilter(args.filters, 'context_data.pir_ids', pirId);
  const finalArgs = {
    ...args,
    filters,
    orderBy: args.orderBy ?? 'timestamp',
    orderMode: args.orderMode ?? 'desc',
    types: [ENTITY_TYPE_PIR_HISTORY, ENTITY_TYPE_HISTORY],
  };
  return await elPaginate(context, user, READ_INDEX_HISTORY, finalArgs as PaginateOpts) as LogConnection;
};

export const findPirContainers = async (
  context: AuthContext,
  user: AuthUser,
  pir: BasicStoreEntityPir,
  opts?: EntityOptions<BasicStoreObject>,
) => {
  await checkEnterpriseEdition(context);
  // fetch filters entities ids
  const pirFilters: FilterGroup[] = pir.pir_criteria.map((c) => JSON.parse(c.filters));
  const pirToIdFilterIds = pirFilters.flatMap((f) => extractFilterKeyValues(RELATION_TO_FILTER, f));
  // fetch the containers containing those ids or containing flagged entities ids
  const flaggedEntitiesFilter = {
    mode: FilterMode.And,
    filters: [{
      key: [INSTANCE_REGARDING_OF],
      values: [
        { key: RELATION_TYPE_SUBFILTER, values: [RELATION_IN_PIR] },
        { key: 'id', values: [pir.id] },
      ],
    }],
    filterGroups: [],
  };
  const containsFilter = {
    mode: FilterMode.Or,
    filters: [
      {
        key: [OBJECT_CONTAINS_FILTER],
        values: pirToIdFilterIds,
      },
      {
        key: [INSTANCE_DYNAMIC_REGARDING_OF],
        values: [
          { key: RELATION_TYPE_SUBFILTER, values: [RELATION_OBJECT] },
          { key: 'dynamic', values: [flaggedEntitiesFilter] },
        ],
      },
    ],
    filterGroups: [],
  };
  const filters = opts?.filters && isFilterGroupNotEmpty(opts.filters)
    ? {
        mode: FilterMode.And,
        filters: [],
        filterGroups: [containsFilter, opts.filters],
      }
    : containsFilter;
  return pageEntitiesConnection(context, user, [ENTITY_TYPE_CONTAINER], { ...opts, filters });
};

export const pirAdd = async (context: AuthContext, user: AuthUser, input: PirAddInput) => {
  await checkEnterpriseEdition(context);
  // -- create Pir --
  const rescanStartDate = now() - (input.pir_rescan_days * 24 * 3600 * 1000); // rescan start date in milliseconds
  const authorized_members = input.authorized_members ?? [
    {
      id: user.id,
      access_right: MEMBER_ACCESS_RIGHT_ADMIN,
    },
    {
      id: MEMBER_ACCESS_ALL,
      access_right: MEMBER_ACCESS_RIGHT_VIEW,
    },
  ];
  const finalInput = {
    ...serializePir(input),
    lastEventId: `${rescanStartDate}-0`,
    authorized_members,
  };
  const created: BasicStoreEntityPir = await createEntity(
    context,
    user,
    finalInput,
    ENTITY_TYPE_PIR,
  );
  const pirId = created.internal_id;

  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'create',
    event_access: 'administration',
    message: `creates Pir \`${created.name}\``,
    context_data: { id: pirId, entity_type: ENTITY_TYPE_PIR, input: finalInput },
  });
  // create rabbit queue for pir
  await registerConnectorQueues(pirId, `Pir ${pirId} queue`, 'internal', 'pir');
  // notify the Pir creation
  return notify(BUS_TOPICS[ENTITY_TYPE_PIR].ADDED_TOPIC, created, user);
};

export const deletePir = async (context: AuthContext, user: AuthUser, pirId: string) => {
  await checkEnterpriseEdition(context);
  // remove the Pir rabbit queue
  try {
    await unregisterConnector(pirId);
  } catch (e) {
    logApp.error('[OPENCTI] Error while unregistering Pir connector', { cause: e });
  }
  // delete the Pir
  return deleteInternalObject(context, user, pirId, ENTITY_TYPE_PIR);
};

export const updatePir = async (context: AuthContext, user: AuthUser, pirId: string, input: EditInput[], opts: { auditLogEnabled?: boolean } = {}) => {
  await checkEnterpriseEdition(context);
  const allowedKeys = ['lastEventId', 'name', 'description'];
  const keys = input.map((i) => i.key);
  if (keys.some((k) => !allowedKeys.includes(k))) {
    throw FunctionalError('Error while updating the PIR, invalid or forbidden key.', { pirId });
  }
  return editInternalObject<StoreEntityPir>(context, user, pirId, ENTITY_TYPE_PIR, input, opts);
};

/**
 * Called when an event of create new relationship matches a Pir criteria.
 * If the source of the relationship is already flagged: update its dependencies,
 * otherwise: create a new in-pir relationship between the source and the PIR.
 *
 * @param context To be able to call engine.
 * @param user User making the request.
 * @param pirStandardId The standard ID of the PIR matched by the relationship.
 * @param input The data needed to create the dependency.
 */
export const pirFlagElement = async (
  context: AuthContext,
  user: AuthUser,
  pirStandardId: string,
  input: PirFlagElementInput,
) => {
  // check rights
  if (!isBypassUser(user)) {
    throw ForbiddenAccess();
  }
  const pir = await getPirWithAccessCheck(context, user, pirStandardId);

  const { relationshipId, sourceId, matchingCriteria, relationshipAuthorId } = input;

  // lock resources
  let lock;
  const lockIds = [sourceId, pir.id];
  try {
    // Try to get the lock in redis
    lock = await lockResources(lockIds);

    const source = await internalLoadById<BasicStoreCommon>(context, user, sourceId);
    if (source) { // if element still exist
      const sourceFlagged = (source[RELATION_IN_PIR] ?? []).includes(pir.id);
      // build dependencies
      const pirDependencies = matchingCriteria.map((criterion) => ({
        dependencies: [{ element_id: relationshipId, author_id: relationshipAuthorId }],
        criterion: {
          ...criterion,
          filters: JSON.stringify(criterion.filters),
        },
      }));

      // create or update the pir relation
      if (sourceFlagged) {
        await updatePirExplanations(context, user, sourceId, pir.id, pirDependencies, lockIds, EditOperation.Add);
      } else {
        await createPirRelation(context, user, sourceId, pir.id, pirDependencies, lockIds);
      }
    }
  } catch (err: any) {
    if (err.name === TYPE_LOCK_ERROR) {
      throw LockTimeoutError({ inputIds: lockIds });
    }
    throw err;
  } finally {
    if (lock) await lock.unlock();
  }

  return pir.id;
};

/**
 * Called when a relationship delete event matches a PIR criteria.
 * The in-pir relationship between the source and the PIR should be either deleted
 * or updated (remove the corresponding dependency)
 *
 * @param context To be able to call engine.
 * @param user User making the request.
 * @param pirStandardId The standard ID of the PIR matched by the relationship.
 * @param input Relationship id and source id.
 */
export const pirUnflagElement = async (
  context: AuthContext,
  user: AuthUser,
  pirStandardId: string,
  input: PirUnflagElementInput,
) => {
  if (!isBypassUser(user)) {
    throw ForbiddenAccess();
  }
  const pir = await getPirWithAccessCheck(context, user, pirStandardId);

  const { relationshipId, sourceId } = input;

  // lock resources
  let lock;
  const lockIds = [sourceId, pir.id];
  try {
    // Try to get the lock in redis
    lock = await lockResources(lockIds);

    // fetch in-pir rels between the entity and the pir
    const rels = await topRelationsList(context, user, RELATION_IN_PIR, { fromId: sourceId, toId: pir.id });
    // eslint-disable-next-line no-restricted-syntax
    for (const rel of rels) {
      const relDependencies = (rel as any).pir_explanation as PirExplanation[];
      // fetch dependencies not concerning the relationship
      const newRelDependencies = relDependencies.filter((dep) => !dep.dependencies
        .map((d) => d.element_id)
        .includes(relationshipId));
      if (newRelDependencies.length === 0) {
        // delete the in-pir relationship between source and PIR
        await deleteRelationsByFromAndTo(context, user, sourceId, pir.id, RELATION_IN_PIR, ABSTRACT_STIX_REF_RELATIONSHIP);
      } else if (newRelDependencies.length < relDependencies.length) {
        // update dependencies
        await updatePirExplanations(context, user, sourceId, pir.id, newRelDependencies, lockIds);
      }
    }
  } catch (err: any) {
    if (err.name === TYPE_LOCK_ERROR) {
      throw LockTimeoutError({ inputIds: lockIds });
    }
    throw err;
  } finally {
    if (lock) await lock.unlock();
  }

  return pir.id;
};

export const pirEditAuthorizedMembers = async (
  context: AuthContext,
  user: AuthUser,
  pirId: string,
  input: MemberAccessInput[],
) => {
  await checkEnterpriseEdition(context);
  const args = {
    entityId: pirId,
    input,
    requiredCapabilities: ['PIRAPI_PIRUPDATE'],
    entityType: ENTITY_TYPE_PIR,
    busTopicKey: ENTITY_TYPE_PIR,
  };
  // @ts-expect-error TODO improve busTopicKey types to avoid this
  return editAuthorizedMembers(context, user, args);
};
