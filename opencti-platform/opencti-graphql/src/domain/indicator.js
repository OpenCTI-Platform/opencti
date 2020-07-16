import moment from 'moment';
import { assoc, descend, head, includes, map, pipe, prop, sortWith, isNil, dissoc, concat } from 'ramda';
import { Promise } from 'bluebird';
import {
  createEntity,
  createRelation,
  escapeString,
  findWithConnectedRelations,
  listEntities,
  loadEntityById,
  now,
} from '../database/grakn';
import { BUS_TOPICS, logger } from '../config/conf';
import { notify } from '../database/redis';
import { buildPagination } from '../database/utils';
import { findById as findMarkingDefinitionById } from './markingDefinition';
import { findById as findKillChainPhaseById } from './killChainPhase';
import { findById as findStixObservableById } from './stixObservable';
import { checkIndicatorSyntax, extractObservables } from '../python/pythonBridge';
import { FunctionalError } from '../config/errors';
import { isStixCyberObservable, generateId, ENTITY_TYPE_INDICATOR, RELATION_BASED_ON } from '../utils/idGenerator';
import { askEnrich } from './enrichment';

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
  return loadEntityById(indicatorId, ENTITY_TYPE_INDICATOR);
};
export const findAll = (args) => {
  return listEntities([ENTITY_TYPE_INDICATOR], ['name', 'alias'], args);
};

export const addIndicator = async (user, indicator, createObservables = true) => {
  if (!isStixCyberObservable(indicator.main_observable_type)) {
    throw FunctionalError(`Observable type ${indicator.main_observable_type} is not supported.`);
  }
  // check indicator syntax
  const check = await checkIndicatorSyntax(indicator.pattern_type.toLowerCase(), indicator.indicator_pattern);
  if (check === false) {
    throw FunctionalError(`Indicator of type ${indicator.pattern_type} is not correctly formatted.`);
  }
  const indicatorToCreate = pipe(
    dissoc('basedOn'),
    assoc('x_opencti_main_observable_type', indicator.x_opencti_main_observable_type),
    assoc('x_opencti_score', isNil(indicator.x_opencti_score) ? 50 : indicator.x_opencti_score),
    assoc('x_opencti_detection', isNil(indicator.x_opencti_detection) ? false : indicator.x_opencti_detection),
    assoc('valid_from', isNil(indicator.valid_from) ? now() : indicator.valid_from),
    assoc('valid_until', isNil(indicator.valid_until) ? await computeValidUntil(indicator) : indicator.valid_until)
  )(indicator);
  // create the linked observables
  let observablesToLink = [];
  const observablesToEnrich = [];
  if (createObservables && indicator.pattern_type === 'stix') {
    try {
      // TODO CHANGE AND EXTRACT OBSERVABLE DIFFERENTLY
      const observables = await extractObservables(indicator.indicator_pattern);
      if (observables && observables.length > 0) {
        observablesToLink = await Promise.all(
          observables.map(async (observable) => {
            // TODO GENERATE THE ID
            const internalId = generateId(indicator.main_observable_type, observable);
            const checkObservable = findStixObservableById(internalId);
            if (isNil(checkObservable)) {
              const stixObservable = pipe(
                dissoc('internal_id'),
                dissoc('standard_stix_id'),
                dissoc('stix_ids'),
                dissoc('confidence'),
                dissoc('x_opencti_main_observable_type'),
                dissoc('x_opencti_score'),
                dissoc('x_opencti_detection'),
                dissoc('valid_from'),
                dissoc('valid_until'),
                dissoc('pattern_type'),
                dissoc('pattern_version'),
                dissoc('pattern'),
                dissoc('created'),
                dissoc('modified')
              )(indicatorToCreate);
              // CREATE THE OBSERVABLE
              // TODO MAP THE DATA
              // concat(stixObservable, observable.data)
              const createdStixObservable = await createEntity(user, stixObservable, observable.type);
              observablesToEnrich.push({ id: createdStixObservable.id, type: observable.type });
              return createdStixObservable.id;
            }
            return internalId;
          })
        );
      }
    } catch (err) {
      logger.info(`Cannot create observable`, { error: err });
    }
  }

  if (indicatorToCreate.basedOn) {
    observablesToLink = concat(indicatorToCreate.basedOn, observablesToLink);
  }
  const created = await createEntity(user, indicatorToCreate, ENTITY_TYPE_INDICATOR);
  // TODO CREATE BASED ON RELATIONSHIPS
  await Promise.all(
    observablesToLink.map((observableToLink) => {
      const input = { fromId: created.id, toId: observableToLink, relationship_type: 'based-on' };
      return createRelation(user, input);
    })
  );
  await Promise.all(
    observablesToEnrich.map((observableToEnrich) => {
      return askEnrich(observableToEnrich.id, observableToEnrich.type);
    })
  );
  return notify(BUS_TOPICS.StixDomainEntity.ADDED_TOPIC, created, user);
};

export const observables = (indicatorId) => {
  return findWithConnectedRelations(
    `match $from isa Indicator; $rel(observables_aggregation:$from, soo:$to) isa ${RELATION_BASED_ON};
    $to isa Stix-Observable;
    $from has internal_id "${escapeString(indicatorId)}"; get;`,
    'to',
    { extraRelKey: 'rel' }
  ).then((data) => buildPagination(0, 0, data, data.length));
};
