import { now } from 'moment';
import type { AuthContext, AuthUser } from '../../types/user';
import { type EntityOptions, internalLoadById, listEntities, listEntitiesPaginated, listRelations, listRelationsPaginated, storeLoadById } from '../../database/middleware-loader';
import { type BasicStoreEntityPir, ENTITY_TYPE_PIR, type PirExplanation } from './pir-types';
import {
  type EditInput,
  EditOperation,
  type FilterGroup,
  OrderingMode,
  type PirAddInput,
  type PirFlagElementInput,
  type PirUnflagElementInput
} from '../../generated/graphql';
import { createEntity, deleteRelationsByFromAndTo, updateAttribute } from '../../database/middleware';
import { publishUserAction } from '../../listener/UserActionListener';
import { notify } from '../../database/redis';
import { BUS_TOPICS, logApp } from '../../config/conf';
import { deleteInternalObject } from '../../domain/internalObject';
import { registerConnectorForPir, unregisterConnectorForIngestion } from '../../domain/connector';
import type { BasicStoreCommon, BasicStoreObject } from '../../types/store';
import { RELATION_IN_PIR } from '../../schema/stixRefRelationship';
import { createPirRel, serializePir, updatePirExplanations } from './pir-utils';
import { FunctionalError } from '../../config/errors';
import { ABSTRACT_STIX_REF_RELATIONSHIP, ENTITY_TYPE_CONTAINER } from '../../schema/general';
import { elRawUpdateByQuery } from '../../database/engine';
import { READ_INDEX_HISTORY } from '../../database/utils';
import { addFilter, extractFilterKeyValues } from '../../utils/filtering/filtering-utils';
import { RELATION_TO_FILTER } from '../../utils/filtering/filtering-constants';

export const findById = (context: AuthContext, user: AuthUser, id: string) => {
  return storeLoadById<BasicStoreEntityPir>(context, user, id, ENTITY_TYPE_PIR);
};

export const findAll = (context: AuthContext, user: AuthUser, opts?: EntityOptions<BasicStoreEntityPir>) => {
  return listEntitiesPaginated<BasicStoreEntityPir>(context, user, [ENTITY_TYPE_PIR], opts);
};

export const findPirContainers = async (context: AuthContext, user: AuthUser, pirId: string, opts?: EntityOptions<BasicStoreObject>) => {
  const pirMetaRelsOpts = {
    count: 100,
    orderBy: 'modified',
    orderMode: OrderingMode.Desc,
    relationship_type: ['in-pir'],
    toId: pirId,
  };
  const stixRefRelationships = await listRelations(context, user, [RELATION_IN_PIR], pirMetaRelsOpts); // TODO PIR listRelations is not of correct type
  const flaggedIds = (stixRefRelationships.edges
    .map((n) => n.node.fromId)
    .filter((n) => !!n) ?? []) as string[];
  const pir = await findById(context, user, pirId);
  const pirFilters: FilterGroup[] = pir.pir_criteria.map((c) => JSON.parse(c.filters));
  const pirToIdFilterIds = pirFilters.flatMap((f) => extractFilterKeyValues(RELATION_TO_FILTER, f));
  const idsOfInterest = [...flaggedIds, ...pirToIdFilterIds];
  if (idsOfInterest.length === 0) {
    idsOfInterest.push('<invalid id>'); // To force empty result in the query result
  }
  const filters = addFilter(opts?.filters, 'objects', idsOfInterest);
  return listEntities(context, user, [ENTITY_TYPE_CONTAINER], { filters }); // TODO PIR specify new type (ConnectorConnection)
};

export const pirAdd = async (context: AuthContext, user: AuthUser, input: PirAddInput) => {
  // -- create Pir --
  const rescanStartDate = now() - (input.pir_rescan_days * 24 * 3600 * 1000); // rescan start date in milliseconds
  const finalInput = {
    ...serializePir(input),
    lastEventId: `${rescanStartDate}-0`,
  };
  const created: BasicStoreEntityPir = await createEntity(
    context,
    user,
    finalInput,
    ENTITY_TYPE_PIR,
  );

  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'create',
    event_access: 'extended',
    message: `creates Pir \`${created.name}\``,
    context_data: { id: created.id, entity_type: ENTITY_TYPE_PIR, input: finalInput },
  });
  // create rabbit queue for pir
  await registerConnectorForPir(context, { id: created.id, ...finalInput });
  // -- notify the Pir creation --
  return notify(BUS_TOPICS[ENTITY_TYPE_PIR].ADDED_TOPIC, created, user);
};

export const deletePir = async (context: AuthContext, user: AuthUser, pirId: string) => {
  // remove the Pir rabbit queue
  try {
    await unregisterConnectorForIngestion(context, pirId);
  } catch (e) {
    logApp.error('[OPENCTI] Error while unregistering Pir connector', { cause: e });
  }
  // remove pir id from historic events
  const source = `
    def pirIdIndex = ctx._source.context_data.pir_ids.indexOf(params.pirId);
    if (pirIdIndex >=0 ) {
       ctx._source.context_data.pir_ids.remove(pirIdIndex);
    }  
  `;
  await elRawUpdateByQuery({
    index: READ_INDEX_HISTORY,
    body: {
      script: { source, params: { pirId } },
      query: {
        term: {
          'context_data.pir_ids.keyword': pirId
        }
      },
    },
  });
  // delete the Pir
  return deleteInternalObject(context, user, pirId, ENTITY_TYPE_PIR);
};

export const updatePir = async (context: AuthContext, user: AuthUser, pirId: string, input: EditInput[]) => {
  const allowedKeys = ['lastEventId', 'name', 'description'];
  const keys = input.map((i) => i.key);
  if (keys.some((k) => !allowedKeys.includes(k))) {
    throw FunctionalError('Error while updating the PIR, invalid or forbidden key.');
  }
  const { element } = await updateAttribute(context, user, pirId, ENTITY_TYPE_PIR, input);
  return notify(BUS_TOPICS[ENTITY_TYPE_PIR].EDIT_TOPIC, element, user);
};

/**
   * Called when an event of create new relationship matches a Pir criteria.
   * If the source of the relationship is already flagged update its dependencies,
   * otherwise create a new meta relationship between the source and the PIR.
   *
   * @param context To be able to call engine.
   * @param user User making the request.
   * @param pirId The ID of the PIR matched by the relationship.
   * @param input The data needed to create the dependency.
   */
export const pirFlagElement = async (
  context: AuthContext,
  user: AuthUser,
  pirId: string,
  input: PirFlagElementInput,
) => {
  const pir = await storeLoadById<BasicStoreEntityPir>(context, user, pirId, ENTITY_TYPE_PIR);
  if (!pir) {
    throw FunctionalError('No PIR found');
  }

  const { relationshipId, sourceId, matchingCriteria, relationshipAuthorId } = input;
  const source = await internalLoadById<BasicStoreCommon>(context, user, sourceId);

  if (source) { // if element still exist
    const sourceFlagged = (source[RELATION_IN_PIR] ?? []).includes(pir.id);
    const pirDependencies = matchingCriteria.map((criterion) => ({
      dependencies: [{ element_id: relationshipId, author_id: relationshipAuthorId }],
      criterion: {
        ...criterion,
        filters: JSON.stringify(criterion.filters)
      },
    }));
    if (sourceFlagged) {
      await updatePirExplanations(context, user, sourceId, pir.id, pirDependencies, EditOperation.Add);
    } else {
      await createPirRel(context, user, sourceId, pir.id, pirDependencies);
    }
  }
  return pir.id;
};

/**
 * Called when an event of delete a relationship matches a PIR criteria.
 *
 * @param context To be able to call engine.
 * @param user User making the request.
 * @param pirId The ID of the PIR matched by the relationship.
 * @param input Relationship id and source id.
 */
export const pirUnflagElement = async (
  context: AuthContext,
  user: AuthUser,
  pirId: string,
  input: PirUnflagElementInput,
) => {
  const pir = await storeLoadById<BasicStoreEntityPir>(context, user, pirId, ENTITY_TYPE_PIR);
  if (!pir) {
    throw FunctionalError('No PIR found');
  }
  const { relationshipId, sourceId } = input;
  // fetch rel between object and pir
  const rels = await listRelationsPaginated(context, user, RELATION_IN_PIR, { fromId: sourceId, toId: pir.id }); // TODO PIR don't use pagination
  // eslint-disable-next-line no-restricted-syntax
  for (const rel of rels.edges) {
    const relDependencies = (rel as any).node.pir_explanations as PirExplanation[];
    // fetch dependencies not concerning the relationship
    const newRelDependencies = relDependencies.filter((dep) => !dep.dependencies
      .map((d) => d.element_id)
      .includes(relationshipId));
    if (newRelDependencies.length === 0) {
      // delete the rel between source and PIR
      await deleteRelationsByFromAndTo(context, user, sourceId, pir.id, RELATION_IN_PIR, ABSTRACT_STIX_REF_RELATIONSHIP);
    } else if (newRelDependencies.length < relDependencies.length) {
      // update dependencies
      await updatePirExplanations(context, user, sourceId, pir.id, newRelDependencies);
    } // nothing to do
  }
  return pir.id;
};
