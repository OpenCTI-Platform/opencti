import moment from 'moment';
import * as R from 'ramda';
import { Promise } from 'bluebird';
import {
  createEntity,
  createRelation,
  batchListThroughGetTo,
  storeLoadById,
  timeSeriesEntities,
  distributionEntities, storeLoadByIdWithRefs,
} from '../database/middleware';
import { listEntities } from '../database/middleware-loader';
import { BUS_TOPICS } from '../config/conf';
import { notify } from '../database/redis';
import { findById as findMarkingDefinitionById } from './markingDefinition';
import { findById as findKillChainPhaseById } from './killChainPhase';
import { checkIndicatorSyntax } from '../python/pythonBridge';
import { DatabaseError, FunctionalError } from '../config/errors';
import { ENTITY_TYPE_INDICATOR } from '../schema/stixDomainObject';
import { isStixCyberObservable } from '../schema/stixCyberObservable';
import { RELATION_BASED_ON, RELATION_INDICATES } from '../schema/stixCoreRelationship';
import {
  ABSTRACT_STIX_CYBER_OBSERVABLE,
  ABSTRACT_STIX_DOMAIN_OBJECT, INPUT_CREATED_BY, INPUT_EXTERNAL_REFS,
  INPUT_LABELS,
  INPUT_MARKINGS
} from '../schema/general';
import { elCount } from '../database/engine';
import { isEmptyField, READ_INDEX_STIX_DOMAIN_OBJECTS } from '../database/utils';
import { extractObservablesFromIndicatorPattern } from '../utils/syntax';

const OpenCTITimeToLive = {
  // Formatted as "[Marking-Definition]-[KillChainPhaseIsDelivery]"
  File: {
    'TLP:CLEAR-no': 365,
    'TLP:CLEAR-yes': 365,
    'TLP:GREEN-no': 365,
    'TLP:GREEN-yes': 365,
    'TLP:AMBER-yes': 365,
    'TLP:AMBER-no': 365,
    'TLP:AMBER+STRICT-yes': 365,
    'TLP:AMBER+STRICT-no': 365,
    'TLP:RED-yes': 365,
    'TLP:RED-no': 365,
  },
  'IPv4-Addr': {
    'TLP:CLEAR-no': 30,
    'TLP:CLEAR-yes': 7,
    'TLP:GREEN-no': 30,
    'TLP:GREEN-yes': 7,
    'TLP:AMBER-yes': 15,
    'TLP:AMBER-no': 60,
    'TLP:AMBER+STRICT-yes': 15,
    'TLP:AMBER+STRICT-no': 60,
    'TLP:RED-yes': 120,
    'TLP:RED-no': 120,
  },
  Url: {
    'TLP:CLEAR-no': 60,
    'TLP:CLEAR-yes': 15,
    'TLP:GREEN-no': 60,
    'TLP:GREEN-yes': 15,
    'TLP:AMBER-yes': 30,
    'TLP:AMBER-no': 180,
    'TLP:AMBER+STRICT-yes': 30,
    'TLP:AMBER+STRICT-no': 180,
    'TLP:RED-yes': 180,
    'TLP:RED-no': 180,
  },
  default: {
    'TLP:CLEAR-no': 365,
    'TLP:CLEAR-yes': 365,
    'TLP:GREEN-no': 365,
    'TLP:GREEN-yes': 365,
    'TLP:AMBER-yes': 365,
    'TLP:AMBER-no': 365,
    'TLP:AMBER+STRICT-yes': 365,
    'TLP:AMBER+STRICT-no': 365,
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
  let markingDefinition = 'TLP:CLEAR';
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
  return storeLoadById(user, indicatorId, ENTITY_TYPE_INDICATOR);
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
        : `Simple observable of indicator {${indicator.name || indicator.pattern}}`,
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

export const promoteIndicatorToObservable = async (user, indicatorId) => {
  const indicator = await storeLoadByIdWithRefs(user, indicatorId);
  const objectLabel = (indicator[INPUT_LABELS] ?? []).map((n) => n.internal_id);
  const objectMarking = (indicator[INPUT_MARKINGS] ?? []).map((n) => n.internal_id);
  const externalReferences = (indicator[INPUT_EXTERNAL_REFS] ?? []).map((n) => n.internal_id);
  const createdBy = indicator[INPUT_CREATED_BY]?.internal_id;
  const input = { objectLabel, objectMarking, createdBy, externalReferences };
  return createObservablesFromIndicator(user, input, indicator);
};

export const addIndicator = async (user, indicator) => {
  const observableType = isEmptyField(indicator.x_opencti_main_observable_type) ? 'Unknown' : indicator.x_opencti_main_observable_type;
  const isKnownObservable = observableType !== 'Unknown';
  if (isKnownObservable && !isStixCyberObservable(indicator.x_opencti_main_observable_type)) {
    throw FunctionalError(`Observable type ${indicator.x_opencti_main_observable_type} is not supported.`);
  }
  // check indicator syntax
  const check = await checkIndicatorSyntax(indicator.pattern_type.toLowerCase(), indicator.pattern);
  if (check === false) {
    throw FunctionalError(`Indicator of type ${indicator.pattern_type} is not correctly formatted.`);
  }
  const validUntil = isEmptyField(indicator.valid_until) ? await computeValidUntil(user, indicator) : indicator.valid_until;
  const indicatorToCreate = R.pipe(
    R.dissoc('createObservables'),
    R.dissoc('basedOn'),
    R.assoc('x_opencti_main_observable_type', observableType),
    R.assoc('x_opencti_score', R.isNil(indicator.x_opencti_score) ? 50 : indicator.x_opencti_score),
    R.assoc('x_opencti_detection', R.isNil(indicator.x_opencti_detection) ? false : indicator.x_opencti_detection),
    R.assoc('valid_from', R.isNil(indicator.valid_from) ? validUntil : indicator.valid_from),
    R.assoc('valid_until', validUntil)
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
  if (observablesToLink.length === 0 && indicator.createObservables) {
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
