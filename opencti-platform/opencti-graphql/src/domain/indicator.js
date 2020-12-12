import moment from 'moment';
import { assoc, descend, dissoc, head, includes, isNil, map, pipe, prop, sortWith } from 'ramda';
import { Promise } from 'bluebird';
import {
  createEntity,
  createRelation,
  listEntities,
  batchListThroughGetTo,
  loadById,
  now,
} from '../database/middleware';
import { BUS_TOPICS } from '../config/conf';
import { notify } from '../database/redis';
import { findById as findMarkingDefinitionById } from './markingDefinition';
import { findById as findKillChainPhaseById } from './killChainPhase';
import { checkIndicatorSyntax } from '../python/pythonBridge';
import { FunctionalError } from '../config/errors';
import { ENTITY_TYPE_INDICATOR } from '../schema/stixDomainObject';
import { isStixCyberObservable } from '../schema/stixCyberObservable';
import { RELATION_BASED_ON } from '../schema/stixCoreRelationship';
import { ABSTRACT_STIX_CYBER_OBSERVABLE, ABSTRACT_STIX_DOMAIN_OBJECT } from '../schema/general';

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
    indicator.x_opencti_main_observable_type && indicator.x_opencti_main_observable_type.includes('File')
      ? 'File'
      : indicator.x_opencti_main_observable_type;
  if (mainObservableType && includes(indicator.x_opencti_main_observable_type, OpenCTITimeToLive)) {
    ttl = OpenCTITimeToLive[indicator.x_opencti_main_observable_type][ttlPattern];
  }
  const validUntil = validFrom.add(ttl, 'days');
  return validUntil.toDate();
};

export const findById = (indicatorId) => {
  return loadById(indicatorId, ENTITY_TYPE_INDICATOR);
};

export const findAll = (args) => {
  return listEntities([ENTITY_TYPE_INDICATOR], args);
};

export const addIndicator = async (user, indicator) => {
  if (
    indicator.x_opencti_main_observable_type !== 'Unknown' &&
    !isStixCyberObservable(indicator.x_opencti_main_observable_type)
  ) {
    throw FunctionalError(`Observable type ${indicator.x_opencti_main_observable_type} is not supported.`);
  }
  // check indicator syntax
  const check = await checkIndicatorSyntax(indicator.pattern_type.toLowerCase(), indicator.pattern);
  if (check === false) {
    throw FunctionalError(`Indicator of type ${indicator.pattern_type} is not correctly formatted.`);
  }
  const indicatorToCreate = pipe(
    dissoc('basedOn'),
    assoc(
      'x_opencti_main_observable_type',
      isNil(indicator.x_opencti_main_observable_type) ? 'Unknown' : indicator.x_opencti_main_observable_type
    ),
    assoc('x_opencti_score', isNil(indicator.x_opencti_score) ? 50 : indicator.x_opencti_score),
    assoc('x_opencti_detection', isNil(indicator.x_opencti_detection) ? false : indicator.x_opencti_detection),
    assoc('valid_from', isNil(indicator.valid_from) ? now() : indicator.valid_from),
    assoc('valid_until', isNil(indicator.valid_until) ? await computeValidUntil(indicator) : indicator.valid_until)
  )(indicator);
  // create the linked observables
  let observablesToLink = [];
  if (indicator.basedOn) {
    observablesToLink = indicator.basedOn;
  }
  const created = await createEntity(user, indicatorToCreate, ENTITY_TYPE_INDICATOR);
  await Promise.all(
    observablesToLink.map((observableToLink) => {
      const input = { fromId: created.id, toId: observableToLink, relationship_type: RELATION_BASED_ON };
      return createRelation(user, input);
    })
  );
  return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].ADDED_TOPIC, created, user);
};

export const batchObservables = (indicatorIds) => {
  return batchListThroughGetTo(indicatorIds, RELATION_BASED_ON, ABSTRACT_STIX_CYBER_OBSERVABLE);
};
