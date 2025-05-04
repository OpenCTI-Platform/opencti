import { v4 as uuidv4 } from 'uuid';
import type { AuthContext, AuthUser } from '../../types/user';
import { type EntityOptions, listEntitiesPaginated, listRelations, storeLoadById } from '../../database/middleware-loader';
import { type BasicStoreEntityPIR, ENTITY_TYPE_PIR, type PirDependency } from './pir-types';
import { FilterMode, FilterOperator, type PirAddInput, type StixCoreRelationshipConnection } from '../../generated/graphql';
import { createEntity } from '../../database/middleware';
import { publishUserAction } from '../../listener/UserActionListener';
import { notify } from '../../database/redis';
import { BUS_TOPICS } from '../../config/conf';
import { ABSTRACT_STIX_CORE_RELATIONSHIP } from '../../schema/general';
import { SYSTEM_USER } from '../../utils/access';
import { addFilter } from '../../utils/filtering/filtering-utils';
import { createPirTask } from '../../domain/backgroundTask';

export const findById = (context: AuthContext, user: AuthUser, id: string) => {
  return storeLoadById<BasicStoreEntityPIR>(context, user, id, ENTITY_TYPE_PIR);
};

export const findAll = (context: AuthContext, user: AuthUser, opts?: EntityOptions<BasicStoreEntityPIR>) => {
  return listEntitiesPaginated<BasicStoreEntityPIR>(context, user, [ENTITY_TYPE_PIR], opts);
};

const PIR_RESCAN_PERIOD = 30 * 24 * 3600 * 1000; // 1 month in milliseconds

export const pirAdd = async (context: AuthContext, user: AuthUser, input: PirAddInput) => {
  // -- create PIR --
  const finalInput = {
    ...input,
    pirCriteria: input.pirCriteria.map((c) => ({
      ...c,
      id: uuidv4(),
    }))
  };
  const created = await createEntity(
    context,
    user,
    finalInput,
    ENTITY_TYPE_PIR,
  );
  const pirId = created.id;
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'create',
    event_access: 'extended',
    message: `creates PIR \`${created.name}\``,
    context_data: { id: pirId, entity_type: ENTITY_TYPE_PIR, input: finalInput },
  });
  // -- rescan past events to find pir dependencies --
  const dependencies: Map<string, PirDependency[]> = new Map();
  const time = new Date().getTime() - PIR_RESCAN_PERIOD;
  const periodFilters = addFilter(undefined, 'start_time', time.toString(), FilterOperator.Gt);
  // eslint-disable-next-line no-restricted-syntax
  for (const criterion of finalInput.pirCriteria) {
    const args = {
      filters: {
        mode: FilterMode.And,
        filters: [],
        filterGroups: [JSON.parse(finalInput.pirFilters), periodFilters, JSON.parse(criterion.filters)],
      },
    };
    const matchingRelationships = await listRelations(context, SYSTEM_USER, ABSTRACT_STIX_CORE_RELATIONSHIP, args);
    // eslint-disable-next-line no-restricted-syntax
    for (const relationship of (matchingRelationships as unknown as StixCoreRelationshipConnection).edges.map((n) => n.node)) {
      const sourceId = relationship.fromId;
      const newDependency = {
        relationship_id: relationship.id,
        weight: criterion.weight,
      };
      const existingDependencies = dependencies.get(sourceId);
      if (existingDependencies) {
        dependencies.set(
          sourceId,
          [
            ...existingDependencies,
            newDependency,
          ]
        );
      } else {
        dependencies.set(sourceId, [newDependency]);
      }
    }
  }
  // -- create the meta refs between sources and the PIR via a background task --
  await createPirTask(context, SYSTEM_USER, { pir_dependencies_map: dependencies, pir_id: pirId });
  // -- notify the PIR creation --
  return notify(BUS_TOPICS[ENTITY_TYPE_PIR].ADDED_TOPIC, created, user);
};
