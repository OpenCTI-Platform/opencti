import moment from 'moment';
import { assoc, concat, descend, dissoc, head, includes, map, pipe, prop, sortWith } from 'ramda';
import { Promise } from 'bluebird';
import {
  createEntity,
  escapeString,
  findWithConnectedRelations,
  listEntities,
  loadEntityById,
  loadEntityByStixId,
  now,
} from '../database/grakn';
import { BUS_TOPICS, logger } from '../config/conf';
import { notify } from '../database/redis';
import { buildPagination, TYPE_STIX_DOMAIN_ENTITY, TYPE_STIX_OBSERVABLE } from '../database/utils';
import { findById as findMarkingDefinitionById } from './markingDefinition';
import { findById as findKillChainPhaseById } from './killChainPhase';
import { askEnrich } from './enrichment';
import { extractObservables } from '../python/pythonBridge';
import { OBSERVABLE_TYPES } from '../database/stix';

const OpenCTITimeToLive = {
  // Formatted as "[Marking-Definition]-[KillChainPhaseIsDelivery]"
  File: {
    'TLP:WHITE-no': 365,
    'TLP:WHITE-yes': 365,
    'TLP:GREEN-no': 365,
    'TLP:GREEN-yes': 365,
    'TLP:AMBER-yes': 365,
    'TLP:AMBER-no': 365,
    'TLP:RED-yes': 365,
    'TLP:RED-no': 365,
  },
  'IPv4-Addr': {
    'TLP:WHITE-no': 30,
    'TLP:WHITE-yes': 7,
    'TLP:GREEN-no': 30,
    'TLP:GREEN-yes': 7,
    'TLP:AMBER-yes': 15,
    'TLP:AMBER-no': 60,
    'TLP:RED-yes': 120,
    'TLP:RED-no': 120,
  },
  URL: {
    'TLP:WHITE-no': 60,
    'TLP:WHITE-yes': 15,
    'TLP:GREEN-no': 60,
    'TLP:GREEN-yes': 15,
    'TLP:AMBER-yes': 30,
    'TLP:AMBER-no': 180,
    'TLP:RED-yes': 180,
    'TLP:RED-no': 180,
  },
  default: {
    'TLP:WHITE-no': 365,
    'TLP:WHITE-yes': 365,
    'TLP:GREEN-no': 365,
    'TLP:GREEN-yes': 365,
    'TLP:AMBER-yes': 365,
    'TLP:AMBER-no': 365,
    'TLP:RED-yes': 365,
    'TLP:RED-no': 365,
  },
};

const computeValidUntil = async (indicator) => {
  let validFrom = moment().utc();
  if (indicator.valid_from) {
    validFrom = moment(indicator.valid_from).utc();
  }
  // get the highest marking definition
  let markingDefinition = 'TLP:WHITE';
  if (indicator.markingDefinitions && indicator.markingDefinitions.length > 0) {
    const markingDefinitions = await Promise.all(
      indicator.markingDefinitions.map((markingDefinitionId) => {
        return findMarkingDefinitionById(markingDefinitionId);
      })
    );
    markingDefinition = pipe(sortWith([descend(prop('level'))]), head, prop('definition'))(markingDefinitions);
  }
  // check if kill chain phase is delivery
  let isKillChainPhaseDelivery = 'no';
  if (indicator.killChainPhases && indicator.killChainPhases.length > 0) {
    const killChainPhases = await Promise.all(
      indicator.killChainPhases.map((killChainPhaseId) => {
        return findKillChainPhaseById(killChainPhaseId);
      })
    );
    const killChainPhasesNames = map((n) => n.phase_name, killChainPhases);
    isKillChainPhaseDelivery =
      includes('initial-access', killChainPhasesNames) || includes('execution', killChainPhasesNames) ? 'yes' : 'no';
  }
  // compute with delivery and marking definition
  const ttlPattern = `${markingDefinition}-${isKillChainPhaseDelivery}`;
  let ttl = OpenCTITimeToLive.default[ttlPattern];
  const mainObservableType =
    indicator.main_observable_type && indicator.main_observable_type.includes('File')
      ? 'File'
      : indicator.main_observable_type;
  if (mainObservableType && includes(indicator.main_observable_type, OpenCTITimeToLive)) {
    ttl = OpenCTITimeToLive[indicator.main_observable_type][ttlPattern];
  }
  const validUntil = validFrom.add(ttl, 'days');
  return validUntil.toDate();
};

export const findById = (indicatorId) => {
  if (indicatorId.match(/[a-z-]+--[\w-]{36}/g)) {
    return loadEntityByStixId(indicatorId, 'Indicator');
  }
  return loadEntityById(indicatorId, 'Indicator');
};
export const findAll = (args) => {
  return listEntities(['Indicator'], ['name', 'alias'], args);
};

export const addIndicator = async (user, indicator, createObservables = true) => {
  if (!OBSERVABLE_TYPES.includes(indicator.main_observable_type.toLowerCase())) {
    throw new Error(`[SCHEMA] Observable type ${indicator.main_observable_type} is not supported.`);
  }
  const indicatorToCreate = pipe(
    assoc('main_observable_type', indicator.main_observable_type.toLowerCase()),
    assoc('score', indicator.score ? indicator.score : 50),
    assoc('valid_from', indicator.valid_from ? indicator.valid_from : now()),
    assoc('valid_until', indicator.valid_until ? indicator.valid_until : await computeValidUntil(indicator))
  )(indicator);
  // create the linked observables
  let observablesToLink = [];
  if (createObservables && indicator.pattern_type === 'stix') {
    try {
      const observables = await extractObservables(indicator.indicator_pattern);
      if (observables && observables.length > 0) {
        observablesToLink = await Promise.all(
          observables.map(async (observable) => {
            const args = {
              parentType: 'Stix-Observable',
              filters: [{ key: 'observable_value', values: [observable.value] }],
            };
            const existingObservables = await listEntities(
              ['Stix-Observable'],
              ['name', 'description', 'observable_value'],
              args
            );
            if (existingObservables.edges.length === 0) {
              const stixObservable = pipe(
                dissoc('internal_id_key'),
                dissoc('stix_id_key'),
                dissoc('main_observable_type'),
                dissoc('score'),
                dissoc('valid_from'),
                dissoc('valid_until'),
                dissoc('pattern_type'),
                dissoc('indicator_pattern'),
                dissoc('created'),
                dissoc('modified'),
                assoc('type', observable.type),
                assoc('observable_value', observable.value)
              )(indicatorToCreate);
              const innerType = stixObservable.type;
              const stixObservableToCreate = dissoc('type', stixObservable);
              const createdStixObservable = await createEntity(user, stixObservableToCreate, innerType, {
                modelType: TYPE_STIX_OBSERVABLE,
                stixIdType: 'observable',
              });
              await askEnrich(createdStixObservable.id, innerType);
              return createdStixObservable.id;
            }
            return existingObservables.edges[0].node.id;
          })
        );
      }
    } catch (err) {
      logger.info(`Cannot create observable > Error ${err}`);
    }
  }
  let observableRefs = [];
  if (indicatorToCreate.observableRefs) {
    observableRefs = concat(indicatorToCreate.observableRefs, observablesToLink);
  } else {
    observableRefs = observablesToLink;
  }
  const created = await createEntity(
    user,
    assoc('observableRefs', observableRefs, indicatorToCreate),
    'Indicator',
    TYPE_STIX_DOMAIN_ENTITY
  );
  return notify(BUS_TOPICS.StixDomainEntity.ADDED_TOPIC, created, user);
};

export const observableRefs = (indicatorId) => {
  return findWithConnectedRelations(
    `match $from isa Indicator; $rel(observables_aggregation:$from, soo:$to) isa observable_refs;
    $to isa Stix-Observable;
    $from has internal_id_key "${escapeString(indicatorId)}"; get;`,
    'to',
    { extraRelKey: 'rel' }
  ).then((data) => buildPagination(0, 0, data, data.length));
};
