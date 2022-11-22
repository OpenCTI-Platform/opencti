import * as R from 'ramda';
import { Promise } from 'bluebird';
import {
  batchListThroughGetTo,
  createEntity,
  createRelation,
  distributionEntities,
  storeLoadById,
  storeLoadByIdWithRefs,
  timeSeriesEntities,
} from '../database/middleware';
import { listEntities } from '../database/middleware-loader';
import { BUS_TOPICS } from '../config/conf';
import { notify } from '../database/redis';
import { checkIndicatorSyntax } from '../python/pythonBridge';
import { DatabaseError, FunctionalError } from '../config/errors';
import { ENTITY_TYPE_INDICATOR } from '../schema/stixDomainObject';
import { isStixCyberObservable } from '../schema/stixCyberObservable';
import { RELATION_BASED_ON, RELATION_INDICATES } from '../schema/stixCoreRelationship';
import {
  ABSTRACT_STIX_CYBER_OBSERVABLE,
  ABSTRACT_STIX_DOMAIN_OBJECT,
  INPUT_CREATED_BY,
  INPUT_EXTERNAL_REFS,
  INPUT_LABELS,
  INPUT_MARKINGS
} from '../schema/general';
import { elCount } from '../database/engine';
import { isEmptyField, READ_INDEX_STIX_DOMAIN_OBJECTS } from '../database/utils';
import { extractObservablesFromIndicatorPattern } from '../utils/syntax';
import { computeValidPeriod } from '../utils/indicator-utils';

export const findById = (context, user, indicatorId) => {
  return storeLoadById(context, user, indicatorId, ENTITY_TYPE_INDICATOR);
};

export const findAll = (context, user, args) => {
  return listEntities(context, user, [ENTITY_TYPE_INDICATOR], args);
};

export const createObservablesFromIndicator = async (context, user, input, indicator) => {
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
    const createdObservable = await createEntity(context, user, observableInput, observable.type);
    observablesToLink.push(createdObservable.id);
  }
  await Promise.all(
    observablesToLink.map((observableToLink) => {
      const relationInput = { fromId: indicator.id, toId: observableToLink, relationship_type: RELATION_BASED_ON };
      return createRelation(context, user, relationInput);
    })
  );
};

export const promoteIndicatorToObservable = async (context, user, indicatorId) => {
  const indicator = await storeLoadByIdWithRefs(context, user, indicatorId);
  const objectLabel = (indicator[INPUT_LABELS] ?? []).map((n) => n.internal_id);
  const objectMarking = (indicator[INPUT_MARKINGS] ?? []).map((n) => n.internal_id);
  const externalReferences = (indicator[INPUT_EXTERNAL_REFS] ?? []).map((n) => n.internal_id);
  const createdBy = indicator[INPUT_CREATED_BY]?.internal_id;
  const input = { objectLabel, objectMarking, createdBy, externalReferences };
  return createObservablesFromIndicator(context, user, input, indicator);
};

export const addIndicator = async (context, user, indicator) => {
  const observableType = isEmptyField(indicator.x_opencti_main_observable_type) ? 'Unknown' : indicator.x_opencti_main_observable_type;
  const isKnownObservable = observableType !== 'Unknown';
  if (isKnownObservable && !isStixCyberObservable(indicator.x_opencti_main_observable_type)) {
    throw FunctionalError(`Observable type ${indicator.x_opencti_main_observable_type} is not supported.`);
  }
  // check indicator syntax
  const check = await checkIndicatorSyntax(context, user, indicator.pattern_type.toLowerCase(), indicator.pattern);
  if (check === false) {
    throw FunctionalError(`Indicator of type ${indicator.pattern_type} is not correctly formatted.`);
  }
  const { validFrom, validUntil } = await computeValidPeriod(context, user, indicator);
  const indicatorToCreate = R.pipe(
    R.dissoc('createObservables'),
    R.dissoc('basedOn'),
    R.assoc('x_opencti_main_observable_type', observableType),
    R.assoc('x_opencti_score', indicator.x_opencti_score ?? 50),
    R.assoc('x_opencti_detection', indicator.x_opencti_detection ?? false),
    R.assoc('valid_from', validFrom),
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
  const created = await createEntity(context, user, indicatorToCreate, ENTITY_TYPE_INDICATOR);
  await Promise.all(
    observablesToLink.map((observableToLink) => {
      const input = { fromId: created.id, toId: observableToLink, relationship_type: RELATION_BASED_ON };
      return createRelation(context, user, input);
    })
  );
  if (observablesToLink.length === 0 && indicator.createObservables) {
    await createObservablesFromIndicator(context, user, indicator, created);
  }
  return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].ADDED_TOPIC, created, user);
};

// region series
export const indicatorsTimeSeries = (context, user, args) => {
  const { indicatorClass } = args;
  const filters = indicatorClass ? [{ isRelation: false, type: 'pattern_type', value: args.pattern_type }] : [];
  return timeSeriesEntities(context, user, ENTITY_TYPE_INDICATOR, filters, args);
};

export const indicatorsNumber = (context, user, args) => ({
  count: elCount(context, user, READ_INDEX_STIX_DOMAIN_OBJECTS, R.assoc('types', [ENTITY_TYPE_INDICATOR], args)),
  total: elCount(
    context,
    user,
    READ_INDEX_STIX_DOMAIN_OBJECTS,
    R.pipe(R.assoc('types', [ENTITY_TYPE_INDICATOR]), R.dissoc('endDate'))(args)
  ),
});

export const indicatorsTimeSeriesByEntity = (context, user, args) => {
  const filters = [{ isRelation: true, type: RELATION_INDICATES, value: args.objectId }];
  return timeSeriesEntities(context, user, ENTITY_TYPE_INDICATOR, filters, args);
};

export const indicatorsNumberByEntity = (context, user, args) => ({
  count: elCount(
    context,
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
    context,
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

export const indicatorsDistributionByEntity = async (context, user, args) => {
  const { objectId } = args;
  const filters = [{ isRelation: true, type: RELATION_INDICATES, value: objectId }];
  return distributionEntities(context, user, ENTITY_TYPE_INDICATOR, filters, args);
};
// endregion

export const batchObservables = (context, user, indicatorIds) => {
  return batchListThroughGetTo(context, user, indicatorIds, RELATION_BASED_ON, ABSTRACT_STIX_CYBER_OBSERVABLE);
};
