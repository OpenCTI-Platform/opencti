import moment from 'moment';
import { getObservableValuesFromPattern } from './indicator-domain';
import { buildKillChainPhases, buildMITREExtensions, buildStixDomain } from '../../database/stix-2-1-converter';
import { STIX_EXT_MITRE, STIX_EXT_OCTI } from '../../types/stix-2-1-extensions';
import type { StixIndicator, StoreEntityIndicator, Stix2Indicator } from './indicator-types';
import { ENTITY_TYPE_INDICATOR } from './indicator-types';
import { isNotEmptyField } from '../../database/utils';
import { assertType, cleanObject, convertToStixDate } from '../../database/stix-converter-utils';
import { buildStixDomain as buildStixDomain2 } from '../../database/stix-2-0-converter';
import type { StoreEntity } from '../../types/store';
import { INPUT_KILLCHAIN } from '../../schema/general';
import type { StixInternalKillChainPhase } from '../../types/stix-2-0-smo';

const convertIndicatorToStix = (instance: StoreEntityIndicator): StixIndicator => {
  const indicator = buildStixDomain(instance);
  // Adding one second to the valid_until if valid_from and valid_until are equals,
  // because according to STIX 2.1 specification the valid_until must be greater than the valid_from.
  const computedValidUntil = (
    isNotEmptyField(instance.valid_from) && isNotEmptyField(instance.valid_until) && instance.valid_until === instance.valid_from
  ) ? moment(instance.valid_from).add(1, 'seconds').toDate() : instance.valid_until;
  return {
    ...indicator,
    name: instance.name,
    description: instance.description,
    indicator_types: instance.indicator_types,
    pattern: instance.pattern,
    pattern_type: instance.pattern_type,
    pattern_version: instance.pattern_version,
    valid_from: convertToStixDate(instance.valid_from),
    valid_until: convertToStixDate(computedValidUntil),
    kill_chain_phases: buildKillChainPhases(instance),
    extensions: {
      [STIX_EXT_OCTI]: cleanObject({
        ...indicator.extensions[STIX_EXT_OCTI],
        detection: instance.x_opencti_detection,
        score: instance.x_opencti_score,
        main_observable_type: instance.x_opencti_main_observable_type,
        observable_values: getObservableValuesFromPattern(instance.pattern, true),
      }),
      [STIX_EXT_MITRE]: buildMITREExtensions(instance),
    },
  } as StixIndicator;
};

export const convertIndicatorToStix_2_0 = (instance: StoreEntity): Stix2Indicator => {
  assertType(ENTITY_TYPE_INDICATOR, instance.entity_type);
  const indicator = instance as StoreEntityIndicator;
  const killChainPhases: Array<StixInternalKillChainPhase> = (instance[INPUT_KILLCHAIN] ?? []).map((k: any) => {
    return cleanObject({
      kill_chain_name: k.kill_chain_name,
      phase_name: k.phase_name,
      x_opencti_order: k.x_opencti_order,
    });
  });
  return {
    ...buildStixDomain2(instance),
    name: instance.name,
    description: instance.description,
    indicator_types: indicator.indicator_types,
    pattern: indicator.pattern,
    pattern_type: indicator.pattern_type,
    pattern_version: indicator.pattern_version,
    valid_from: convertToStixDate(indicator.valid_from),
    valid_until: convertToStixDate(indicator.valid_until),
    kill_chain_phases: killChainPhases,
    x_opencti_score: indicator.x_opencti_score,
    x_opencti_detection: indicator.x_opencti_detection,
    x_opencti_main_observable_type: indicator.x_opencti_main_observable_type,
    x_mitre_platforms: indicator.x_mitre_platforms,
  };
};

export default convertIndicatorToStix;
