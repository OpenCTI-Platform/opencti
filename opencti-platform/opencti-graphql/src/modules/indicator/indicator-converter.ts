import moment from 'moment';
import { buildKillChainPhases, buildMITREExtensions, buildStixDomain, cleanObject, convertToStixDate } from '../../database/stix-converter';
import { STIX_EXT_MITRE, STIX_EXT_OCTI } from '../../types/stix-extensions';
import type { StixIndicator, StoreEntityIndicator } from './indicator-types';
import { isNotEmptyField } from '../../database/utils';

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
        main_observable_type: instance.x_opencti_main_observable_type
      }),
      [STIX_EXT_MITRE]: buildMITREExtensions(instance)
    }
  } as StixIndicator;
};

export default convertIndicatorToStix;
