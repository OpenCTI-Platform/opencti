var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
import { MARKING_TLP_AMBER, MARKING_TLP_AMBER_STRICT, MARKING_TLP_CLEAR, MARKING_TLP_GREEN, MARKING_TLP_RED, STATIC_MARKING_IDS } from '../../schema/identifier';
import { getEntitiesMapFromCache } from '../../database/cache';
import { ENTITY_TYPE_MARKING_DEFINITION } from '../../schema/stixMetaObject';
import { isNotEmptyField } from '../../database/utils';
import { utcDate } from '../../utils/format';
export const DEFAULT_INDICATOR_TTL = 365;
const INDICATOR_TTL_DEFINITION = [
    {
        target: ['IPv4-Addr', 'IPv6-Addr'],
        definition: {
            [MARKING_TLP_CLEAR]: 30,
            [MARKING_TLP_GREEN]: 30,
            [MARKING_TLP_AMBER]: 30,
            [MARKING_TLP_AMBER_STRICT]: 60,
            [MARKING_TLP_RED]: 60,
        },
        default: 60
    },
    {
        target: ['File'],
        default: DEFAULT_INDICATOR_TTL
    },
    {
        target: ['Url'],
        definition: {
            [MARKING_TLP_CLEAR]: 60,
            [MARKING_TLP_GREEN]: 60,
            [MARKING_TLP_AMBER]: 180,
            [MARKING_TLP_AMBER_STRICT]: 180,
            [MARKING_TLP_RED]: 180,
        },
        default: 180
    },
];
export const computeValidTTL = (context, user, indicator) => __awaiter(void 0, void 0, void 0, function* () {
    const observableType = indicator.x_opencti_main_observable_type;
    if (observableType) {
        const data = INDICATOR_TTL_DEFINITION.find((ttl) => ttl.target.includes(observableType));
        if (data) {
            if (data.definition && indicator.objectMarking && indicator.objectMarking.length > 0) {
                // Resolve the markings and get the higher rank for TLP
                const markingsMap = yield getEntitiesMapFromCache(context, user, ENTITY_TYPE_MARKING_DEFINITION);
                const topTlpMarking = indicator.objectMarking
                    .map((id) => markingsMap.get(id))
                    .filter((marking) => marking !== null && marking !== undefined)
                    .filter((marking) => STATIC_MARKING_IDS.includes(marking.standard_id))
                    .sort((a, b) => b.x_opencti_order - a.x_opencti_order)
                    .at(0);
                if (topTlpMarking) {
                    return data.definition[topTlpMarking.standard_id];
                }
            }
            return data.default;
        }
    }
    return DEFAULT_INDICATOR_TTL;
});
const computeValidFrom = (indicator) => {
    if (isNotEmptyField(indicator.valid_from)) {
        return utcDate(indicator.valid_from);
    }
    if (isNotEmptyField(indicator.created)) {
        return utcDate(indicator.created);
    }
    return utcDate();
};
const computeValidUntil = (indicator, validFrom, decayRule) => __awaiter(void 0, void 0, void 0, function* () {
    if (isNotEmptyField(indicator.valid_until)) {
        return utcDate(indicator.valid_until);
    }
    const ttl = decayRule.decay_lifetime; // await computeValidTTL(context, user, indicator, decayRule);
    return validFrom.clone().add(ttl, 'days');
});
export const computeValidPeriod = (indicator, decayRule) => __awaiter(void 0, void 0, void 0, function* () {
    const validFrom = computeValidFrom(indicator);
    const validUntil = yield computeValidUntil(indicator, validFrom, decayRule);
    return {
        validFrom,
        validUntil,
        revoked: validUntil.isBefore(utcDate()),
        validPeriod: validFrom.isSameOrBefore(validUntil)
    };
});
