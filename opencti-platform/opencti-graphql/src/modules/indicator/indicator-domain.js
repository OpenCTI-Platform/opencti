var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
import * as R from 'ramda';
import moment from 'moment/moment';
import { createEntity, createRelation, distributionEntities, patchAttribute, storeLoadByIdWithRefs, timeSeriesEntities } from '../../database/middleware';
import { listAllEntities, listEntitiesPaginated, listEntitiesThroughRelationsPaginated, storeLoadById } from '../../database/middleware-loader';
import { BUS_TOPICS, logApp } from '../../config/conf';
import { notify } from '../../database/redis';
import { checkIndicatorSyntax } from '../../python/pythonBridge';
import { DatabaseError, FunctionalError } from '../../config/errors';
import { isStixCyberObservable } from '../../schema/stixCyberObservable';
import { RELATION_BASED_ON, RELATION_INDICATES } from '../../schema/stixCoreRelationship';
import { ABSTRACT_STIX_CYBER_OBSERVABLE, ABSTRACT_STIX_DOMAIN_OBJECT, buildRefRelationKey, INPUT_CREATED_BY, INPUT_EXTERNAL_REFS, INPUT_LABELS, INPUT_MARKINGS } from '../../schema/general';
import { elCount } from '../../database/engine';
import { isEmptyField, READ_INDEX_STIX_DOMAIN_OBJECTS } from '../../database/utils';
import { cleanupIndicatorPattern, extractObservablesFromIndicatorPattern } from '../../utils/syntax';
import { computeValidPeriod } from './indicator-utils';
import { addFilter } from '../../utils/filtering/filtering-utils';
import { ENTITY_TYPE_INDICATOR } from './indicator-types';
import { FilterMode, FilterOperator, OrderingMode } from '../../generated/graphql';
import { BUILT_IN_DECAY_RULES, computeLivePoints, computeLiveScore, computeNextScoreReactionDate, findDecayRuleForIndicator } from './decay-domain';
import { isModuleActivated } from '../../domain/settings';
import { prepareDate } from '../../utils/format';
import { computeChartDecayAlgoSerie, computeScoreList } from './decay-chart-domain';
export const findById = (context, user, indicatorId) => {
    return storeLoadById(context, user, indicatorId, ENTITY_TYPE_INDICATOR);
};
export const findAll = (context, user, args) => {
    return listEntitiesPaginated(context, user, [ENTITY_TYPE_INDICATOR], args);
};
/**
 * Compute live decay detail for an indicator.
 * @param context
 * @param user
 * @param indicator
 */
export const getDecayDetails = (context, user, indicator) => __awaiter(void 0, void 0, void 0, function* () {
    if (!indicator.decay_applied_rule) {
        return null;
    }
    const details = {
        live_score: computeLiveScore(indicator),
        live_points: computeLivePoints(indicator),
    };
    return details;
});
export const getDecayChartData = (context, user, indicator) => __awaiter(void 0, void 0, void 0, function* () {
    if (!indicator.decay_applied_rule) {
        return null;
    }
    const scoreList = computeScoreList(indicator.decay_base_score);
    const liveScoreSerie = computeChartDecayAlgoSerie(indicator, scoreList);
    const chartData = {
        live_score_serie: liveScoreSerie,
    };
    return chartData;
});
export const findIndicatorsForDecay = (context, user, maxSize) => {
    const filters = {
        orderBy: 'decay_next_reaction_date',
        orderMode: OrderingMode.Asc,
        mode: FilterMode.And,
        filters: [
            { key: ['decay_next_reaction_date'], values: [prepareDate()], operator: FilterOperator.Lt },
            { key: ['revoked'], values: ['false'] },
        ],
        filterGroups: [],
    };
    const args = {
        filters,
        maxSize,
    };
    return listAllEntities(context, user, [ENTITY_TYPE_INDICATOR], args);
};
export const createObservablesFromIndicator = (context, user, input, indicator) => __awaiter(void 0, void 0, void 0, function* () {
    const { pattern } = indicator;
    const observables = extractObservablesFromIndicatorPattern(pattern);
    const observablesToLink = [];
    for (let index = 0; index < observables.length; index += 1) {
        const observable = observables[index];
        const observableInput = Object.assign(Object.assign({}, R.dissoc('type', observable)), { x_opencti_description: indicator.description
                ? indicator.description
                : `Simple observable of indicator {${indicator.name || indicator.pattern}}`, x_opencti_score: indicator.x_opencti_score, createdBy: input.createdBy, objectMarking: input.objectMarking, objectLabel: input.objectLabel, externalReferences: input.externalReferences, update: true });
        try {
            const createdObservable = yield createEntity(context, user, observableInput, observable.type);
            observablesToLink.push(createdObservable.id);
        }
        catch (err) {
            logApp.error(err, { input: observableInput });
        }
    }
    yield Promise.all(observablesToLink.map((observableToLink) => {
        const relationInput = { fromId: indicator.id, toId: observableToLink, relationship_type: RELATION_BASED_ON };
        return createRelation(context, user, relationInput);
    }));
});
export const promoteIndicatorToObservable = (context, user, indicatorId) => __awaiter(void 0, void 0, void 0, function* () {
    var _a, _b, _c, _d;
    const indicator = yield storeLoadByIdWithRefs(context, user, indicatorId);
    const objectLabel = ((_a = indicator[INPUT_LABELS]) !== null && _a !== void 0 ? _a : []).map((n) => n.internal_id);
    const objectMarking = ((_b = indicator[INPUT_MARKINGS]) !== null && _b !== void 0 ? _b : []).map((n) => n.internal_id);
    const externalReferences = ((_c = indicator[INPUT_EXTERNAL_REFS]) !== null && _c !== void 0 ? _c : []).map((n) => n.internal_id);
    const createdBy = (_d = indicator[INPUT_CREATED_BY]) === null || _d === void 0 ? void 0 : _d.internal_id;
    const input = { objectLabel, objectMarking, createdBy, externalReferences };
    return createObservablesFromIndicator(context, user, input, indicator);
});
export const addIndicator = (context, user, indicator) => __awaiter(void 0, void 0, void 0, function* () {
    var _e, _f;
    let observableType = isEmptyField(indicator.x_opencti_main_observable_type) ? 'Unknown' : indicator.x_opencti_main_observable_type;
    if (observableType === 'File') {
        observableType = 'StixFile';
    }
    const isKnownObservable = observableType !== 'Unknown';
    if (isKnownObservable && !isStixCyberObservable(observableType)) {
        throw FunctionalError(`Observable type ${observableType} is not supported.`);
    }
    // check indicator syntax
    const patternType = indicator.pattern_type.toLowerCase();
    const formattedPattern = cleanupIndicatorPattern(patternType, indicator.pattern);
    const check = yield checkIndicatorSyntax(context, user, patternType, formattedPattern);
    if (check === false) {
        throw FunctionalError(`Indicator of type ${indicator.pattern_type} is not correctly formatted.`);
    }
    const indicatorBaseScore = (_e = indicator.x_opencti_score) !== null && _e !== void 0 ? _e : 50;
    const isDecayActivated = yield isModuleActivated('INDICATOR_DECAY_MANAGER');
    // find default decay rule (even if decay is not activated, it is used to compute default validFrom and validUntil)
    const decayRule = findDecayRuleForIndicator(observableType, BUILT_IN_DECAY_RULES);
    const { validFrom, validUntil, revoked, validPeriod } = yield computeValidPeriod(indicator, decayRule);
    const indicatorToCreate = R.pipe(R.dissoc('createObservables'), R.dissoc('basedOn'), R.assoc('pattern', formattedPattern), R.assoc('x_opencti_main_observable_type', observableType), R.assoc('x_opencti_score', indicatorBaseScore), R.assoc('x_opencti_detection', (_f = indicator.x_opencti_detection) !== null && _f !== void 0 ? _f : false), R.assoc('valid_from', validFrom.toISOString()), R.assoc('valid_until', validUntil.toISOString()), R.assoc('revoked', revoked))(indicator);
    let finalIndicatorToCreate;
    if (isDecayActivated) {
        const indicatorDecayRule = {
            decay_lifetime: decayRule.decay_lifetime,
            decay_pound: decayRule.decay_pound,
            decay_points: [...decayRule.decay_points],
            decay_revoke_score: decayRule.decay_revoke_score,
        };
        const nextScoreReactionDate = computeNextScoreReactionDate(indicatorBaseScore, indicatorBaseScore, decayRule, validFrom);
        const decayHistory = [];
        decayHistory.push({
            updated_at: validFrom.toDate(),
            score: indicatorBaseScore,
        });
        finalIndicatorToCreate = Object.assign(Object.assign({}, indicatorToCreate), { decay_next_reaction_date: nextScoreReactionDate, decay_base_score: indicatorBaseScore, decay_base_score_date: validFrom.toISOString(), decay_applied_rule: indicatorDecayRule, decay_history: decayHistory });
    }
    else {
        finalIndicatorToCreate = Object.assign({}, indicatorToCreate);
    }
    // create the linked observables
    let observablesToLink = [];
    if (indicator.basedOn) {
        observablesToLink = indicator.basedOn;
    }
    if (!validPeriod) {
        throw DatabaseError('You cant create an indicator with valid_until less than valid_from', {
            input: finalIndicatorToCreate,
        });
    }
    const created = yield createEntity(context, user, finalIndicatorToCreate, ENTITY_TYPE_INDICATOR);
    yield Promise.all(observablesToLink.map((observableToLink) => {
        const input = { fromId: created.id, toId: observableToLink, relationship_type: RELATION_BASED_ON };
        return createRelation(context, user, input);
    }));
    if (observablesToLink.length === 0 && indicator.createObservables) {
        yield createObservablesFromIndicator(context, user, indicator, created);
    }
    return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].ADDED_TOPIC, created, user);
});
export const computeIndicatorDecayPatch = (indicator) => {
    var _a;
    let patch = {};
    const model = indicator.decay_applied_rule;
    if (!model || !model.decay_points) {
        return null;
    }
    const newStableScore = model.decay_points.find((p) => (p || indicator.x_opencti_score) < indicator.x_opencti_score) || model.decay_revoke_score;
    if (newStableScore) {
        const decayHistory = [...((_a = indicator.decay_history) !== null && _a !== void 0 ? _a : [])];
        decayHistory.push({
            updated_at: new Date(),
            score: newStableScore,
        });
        patch = {
            x_opencti_score: newStableScore,
            decay_history: decayHistory,
        };
        if (newStableScore <= model.decay_revoke_score) {
            patch = Object.assign(Object.assign({}, patch), { revoked: true });
        }
        else {
            const nextScoreReactionDate = computeNextScoreReactionDate(indicator.decay_base_score, newStableScore, model, moment(indicator.valid_from));
            if (nextScoreReactionDate) {
                patch = Object.assign(Object.assign({}, patch), { decay_next_reaction_date: nextScoreReactionDate });
            }
        }
    }
    return patch;
};
/**
 * Triggered by the decay manager when decay_next_reaction_date is reached.
 * Compute the next step for Indicator as patch to applied to the database:
 * - change the current stable score to next
 * - update the decay_next_reaction_date to next one
 * - revoke if the revoke score is reached
 * @param context
 * @param user
 * @param indicator
 */
export const updateIndicatorDecayScore = (context, user, indicator) => __awaiter(void 0, void 0, void 0, function* () {
    // update x_opencti_score
    const patch = computeIndicatorDecayPatch(indicator);
    if (!patch) {
        return null;
    }
    return patchAttribute(context, user, indicator.id, ENTITY_TYPE_INDICATOR, patch);
});
// region series
export const indicatorsTimeSeries = (context, user, args) => {
    return timeSeriesEntities(context, user, [ENTITY_TYPE_INDICATOR], args);
};
export const indicatorsTimeSeriesByEntity = (context, user, args) => {
    const { objectId } = args;
    const filters = addFilter(args.filters, buildRefRelationKey(RELATION_INDICATES, '*'), objectId);
    return timeSeriesEntities(context, user, [ENTITY_TYPE_INDICATOR], Object.assign(Object.assign({}, args), { filters }));
};
export const indicatorsNumber = (context, user, args) => __awaiter(void 0, void 0, void 0, function* () {
    const countPromise = elCount(context, user, READ_INDEX_STIX_DOMAIN_OBJECTS, Object.assign(Object.assign({}, args), { types: [ENTITY_TYPE_INDICATOR] }));
    const totalPromise = elCount(context, user, READ_INDEX_STIX_DOMAIN_OBJECTS, Object.assign(Object.assign({}, R.dissoc('endDate', args)), { types: [ENTITY_TYPE_INDICATOR] }));
    const [count, total] = yield Promise.all([countPromise, totalPromise]);
    return { count, total };
});
export const indicatorsNumberByEntity = (context, user, args) => __awaiter(void 0, void 0, void 0, function* () {
    const { objectId } = args;
    const filters = addFilter(null, buildRefRelationKey(RELATION_INDICATES, '*'), objectId);
    const countPromise = elCount(context, user, READ_INDEX_STIX_DOMAIN_OBJECTS, Object.assign(Object.assign({}, args), { types: [ENTITY_TYPE_INDICATOR], filters }));
    const totalPromise = elCount(context, user, READ_INDEX_STIX_DOMAIN_OBJECTS, Object.assign(Object.assign({}, R.dissoc('endDate', args)), { types: [ENTITY_TYPE_INDICATOR], filters }));
    const [count, total] = yield Promise.all([countPromise, totalPromise]);
    return { count, total };
});
export const indicatorsDistributionByEntity = (context, user, args) => __awaiter(void 0, void 0, void 0, function* () {
    const { objectId } = args;
    const filters = addFilter(args.filters, buildRefRelationKey(RELATION_INDICATES, '*'), objectId);
    return distributionEntities(context, user, [ENTITY_TYPE_INDICATOR], Object.assign(Object.assign({}, args), { filters }));
});
// endregion
export const observablesPaginated = (context, user, indicatorId, args) => __awaiter(void 0, void 0, void 0, function* () {
    return listEntitiesThroughRelationsPaginated(context, user, indicatorId, RELATION_BASED_ON, ABSTRACT_STIX_CYBER_OBSERVABLE, false, args);
});
