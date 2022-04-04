import moment from 'moment';
import * as R from 'ramda';
import { Promise } from 'bluebird';
import { dissoc, pipe } from 'ramda';
import {
  createEntity,
  createRelation,
  batchListThroughGetTo,
  loadById,
  timeSeriesEntities,
  distributionEntities,
} from '../database/middleware';
import { listEntities } from '../database/repository';
import { BUS_TOPICS } from '../config/conf';
import { notify } from '../database/redis';
import { findById as findMarkingDefinitionById } from './markingDefinition';
import { findById as findKillChainPhaseById } from './killChainPhase';
import { checkIndicatorSyntax } from '../python/pythonBridge';
import { DatabaseError, FunctionalError } from '../config/errors';
import { ENTITY_TYPE_INDICATOR } from '../schema/stixDomainObject';
import { isStixCyberObservable } from '../schema/stixCyberObservable';
import { RELATION_BASED_ON, RELATION_INDICATES } from '../schema/stixCoreRelationship';
import { ABSTRACT_STIX_CYBER_OBSERVABLE, ABSTRACT_STIX_DOMAIN_OBJECT } from '../schema/general';
import { now } from '../utils/format';
import { elCount } from '../database/engine';
import { READ_INDEX_STIX_DOMAIN_OBJECTS } from '../database/utils';
import { extractObservablesFromIndicatorPattern } from '../utils/syntax';

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
  Url: {
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

const computeValidUntil = async (user, indicator) => {
  let validFrom = moment().utc();
  if (indicator.valid_from) {
    validFrom = moment(indicator.valid_from).utc();
  }
  // get the highest marking definition
  let markingDefinition = 'TLP:WHITE';
  if (indicator.objectMarking && indicator.objectMarking.length > 0) {
    const markingDefinitions = await Promise.all(
      indicator.objectMarking.map((markingDefinitionId) => {
        return findMarkingDefinitionById(user, markingDefinitionId);
      })
    );
    markingDefinition = R.pipe(
      R.sortWith([R.descend(R.prop('level'))]),
      R.head,
      R.prop('definition')
    )(markingDefinitions);
  }
  // check if kill chain phase is delivery
  let isKillChainPhaseDelivery = 'no';
  if (indicator.killChainPhases && indicator.killChainPhases.length > 0) {
    const killChainPhases = await Promise.all(
      indicator.killChainPhases.map((killChainPhaseId) => {
        return findKillChainPhaseById(user, killChainPhaseId);
      })
    );
    const killChainPhasesNames = R.map((n) => n.phase_name, killChainPhases);
    isKillChainPhaseDelivery = R.includes('initial-access', killChainPhasesNames) || R.includes('execution', killChainPhasesNames)
      ? 'yes'
      : 'no';
  }
  // compute with delivery and marking definition
  const ttlPattern = `${markingDefinition}-${isKillChainPhaseDelivery}`;
  let ttl = OpenCTITimeToLive.default[ttlPattern];
  const mainObservableType = indicator.x_opencti_main_observable_type && indicator.x_opencti_main_observable_type.includes('File')
    ? 'File'
    : indicator.x_opencti_main_observable_type;
  if (mainObservableType && R.has(indicator.x_opencti_main_observable_type, OpenCTITimeToLive)) {
    ttl = OpenCTITimeToLive[indicator.x_opencti_main_observable_type][ttlPattern];
  }
  const validUntil = validFrom.add(ttl, 'days');
  return validUntil.toDate();
};

export const findById = (user, indicatorId) => {
  return loadById(user, indicatorId, ENTITY_TYPE_INDICATOR);
};

export const findAll = (user, args) => {
  return listEntities(user, [ENTITY_TYPE_INDICATOR], args);
};

export const createObservablesFromIndicator = async (user, input, indicator) => {
  const { pattern } = indicator;
  const observables = extractObservablesFromIndicatorPattern(pattern);
  const observablesToLink = [];
  for (let index = 0; index < observables.length; index += 1) {
    const observable = observables[index];
    const observableInput = {
      ...R.dissoc('type', observable),
      x_opencti_description: indicator.description
        ? indicator.description
        : `Simple observable of indicator {${indicator.indicator_name}}`,
      x_opencti_score: indicator.x_opencti_score,
      createdBy: input.createdBy,
      objectMarking: input.objectMarking,
      objectLabel: input.objectLabel,
      externalReferences: input.externalReferences,
      update: true,
    };
    const createdObservable = await createEntity(user, observableInput, observable.type);
    observablesToLink.push(createdObservable.id);
  }
  await Promise.all(
    observablesToLink.map((observableToLink) => {
      const relationInput = { fromId: indicator.id, toId: observableToLink, relationship_type: RELATION_BASED_ON };
      return createRelation(user, relationInput);
    })
  );
};

export const addIndicator = async (user, indicator) => {
  if (
    indicator.x_opencti_main_observable_type !== 'Unknown'
    && !isStixCyberObservable(indicator.x_opencti_main_observable_type)
  ) {
    throw FunctionalError(`Observable type ${indicator.x_opencti_main_observable_type} is not supported.`);
  }
  // check indicator syntax
  const check = await checkIndicatorSyntax(indicator.pattern_type.toLowerCase(), indicator.pattern);
  if (check === false) {
    throw FunctionalError(`Indicator of type ${indicator.pattern_type} is not correctly formatted.`);
  }
  const indicatorToCreate = R.pipe(
    R.dissoc('basedOn'),
    R.assoc(
      'x_opencti_main_observable_type',
      R.isNil(indicator.x_opencti_main_observable_type) ? 'Unknown' : indicator.x_opencti_main_observable_type
    ),
    R.assoc('x_opencti_score', R.isNil(indicator.x_opencti_score) ? 50 : indicator.x_opencti_score),
    R.assoc('x_opencti_detection', R.isNil(indicator.x_opencti_detection) ? false : indicator.x_opencti_detection),
    R.assoc('valid_from', R.isNil(indicator.valid_from) ? now() : indicator.valid_from),
    R.assoc(
      'valid_until',
      R.isNil(indicator.valid_until) ? await computeValidUntil(user, indicator) : indicator.valid_until
    )
  )(indicator);
  // create the linked observables
  let observablesToLink = [];
  if (indicator.basedOn) {
    observablesToLink = indicator.basedOn;
  }
  if (indicatorToCreate.valid_from > indicatorToCreate.valid_until) {
    throw DatabaseError('You cant create an indicator with valid_until less than valid_from', {
      input: indicatorToCreate,
    });
  }
  const created = await createEntity(user, indicatorToCreate, ENTITY_TYPE_INDICATOR);
  await Promise.all(
    observablesToLink.map((observableToLink) => {
      const input = { fromId: created.id, toId: observableToLink, relationship_type: RELATION_BASED_ON };
      return createRelation(user, input);
    })
  );
  if (observablesToLink.length === 0) {
    await createObservablesFromIndicator(user, indicator, created);
  }
  return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].ADDED_TOPIC, created, user);
};

// region series
export const indicatorsTimeSeries = (user, args) => {
  const { indicatorClass } = args;
  const filters = indicatorClass ? [{ isRelation: false, type: 'pattern_type', value: args.pattern_type }] : [];
  return timeSeriesEntities(user, ENTITY_TYPE_INDICATOR, filters, args);
};

export const indicatorsNumber = (user, args) => ({
  count: elCount(user, READ_INDEX_STIX_DOMAIN_OBJECTS, R.assoc('types', [ENTITY_TYPE_INDICATOR], args)),
  total: elCount(
    user,
    READ_INDEX_STIX_DOMAIN_OBJECTS,
    R.pipe(R.assoc('types', [ENTITY_TYPE_INDICATOR]), R.dissoc('endDate'))(args)
  ),
});

export const indicatorsTimeSeriesByEntity = (user, args) => {
  const filters = [{ isRelation: true, type: RELATION_INDICATES, value: args.objectId }];
  return timeSeriesEntities(user, ENTITY_TYPE_INDICATOR, filters, args);
};

export const indicatorsNumberByEntity = (user, args) => ({
  count: elCount(
    user,
    READ_INDEX_STIX_DOMAIN_OBJECTS,
    R.pipe(
      R.assoc('isMetaRelationship', true),
      R.assoc('types', [ENTITY_TYPE_INDICATOR]),
      R.assoc('relationshipType', RELATION_INDICATES),
      R.assoc('fromId', args.objectId)
    )(args)
  ),
  total: elCount(
    user,
    READ_INDEX_STIX_DOMAIN_OBJECTS,
    R.pipe(
      R.assoc('isMetaRelationship', true),
      R.assoc('types', [ENTITY_TYPE_INDICATOR]),
      R.assoc('relationshipType', RELATION_INDICATES),
      R.assoc('fromId', args.objectId),
      R.dissoc('endDate')
    )(args)
  ),
});

export const indicatorsDistributionByEntity = async (user, args) => {
  const { objectId } = args;
  const filters = [{ isRelation: true, type: RELATION_INDICATES, value: objectId }];
  return distributionEntities(user, ENTITY_TYPE_INDICATOR, filters, args);
};
// endregion

export const batchObservables = (user, indicatorIds) => {
  return batchListThroughGetTo(user, indicatorIds, RELATION_BASED_ON, ABSTRACT_STIX_CYBER_OBSERVABLE);
};
