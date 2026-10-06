import { buildStixDomain } from '../../database/stix-2-1-converter';
import { cleanObject } from '../../database/stix-converter-utils';
import { STIX_EXT_OCTI, STIX_EXT_OCTI_HUNT } from '../../types/stix-2-1-extensions';
import {
  ATTRIBUTE_HUNT_SOURCES,
  ATTRIBUTE_HUNT_TARGETS,
  ATTRIBUTE_HUNT_TECHNIQUES,
  INPUT_HUNT_SOURCES,
  INPUT_HUNT_TARGETS,
  INPUT_HUNT_TECHNIQUES,
  type StixHunt,
  type StoreEntityHunt,
} from './hunt-types';

const convertHuntToStix = (instance: StoreEntityHunt): StixHunt => {
  const stixDomainObject = buildStixDomain(instance);
  return {
    ...stixDomainObject,
    name: instance.name,
    description: instance.description ?? '',
    hypothesis: instance.hypothesis ?? '',
    hunt_type: instance.hunt_type,
    hunt_status: instance.hunt_status,
    hunt_source_kind: instance.hunt_source_kind,
    sigma_rule: instance.sigma_rule ?? '',
    native_queries: (instance.native_queries ?? []).map((nativeQuery) => cleanObject({ ...nativeQuery })),
    hunt_ioc_filters: instance.hunt_ioc_filters ?? '',
    hunt_ioc_values: (instance.hunt_ioc_values ?? []).map((value) => ({ observable_type: value.observable_type, value: value.value })),
    hunt_scope: instance.hunt_scope ?? '',
    hunt_schedule: instance.hunt_schedule,
    trigger_filters: instance.trigger_filters ?? '',
    hunt_pir_activation: instance.hunt_pir_activation ?? false,
    time_window_hours: instance.time_window_hours,
    expected_observables: instance.expected_observables ?? [],
    benign_patterns: instance.benign_patterns ?? [],
    escalation_threshold: instance.escalation_threshold,
    escalate_manual_runs: instance.escalate_manual_runs ?? false,
    hunt_max_results: instance.hunt_max_results,
    [ATTRIBUTE_HUNT_TARGETS]: (instance[INPUT_HUNT_TARGETS] ?? []).map((target) => target.standard_id),
    [ATTRIBUTE_HUNT_TECHNIQUES]: (instance[INPUT_HUNT_TECHNIQUES] ?? []).map((technique) => technique.standard_id),
    [ATTRIBUTE_HUNT_SOURCES]: (instance[INPUT_HUNT_SOURCES] ?? []).map((source) => source.standard_id),
    extensions: {
      [STIX_EXT_OCTI]: cleanObject({
        ...stixDomainObject.extensions[STIX_EXT_OCTI],
        extension_type: 'new-sdo',
      }),
      // Declares the hunt schema to non OpenCTI consumers, carried by hunt packs as an extension-definition object
      [STIX_EXT_OCTI_HUNT]: { extension_type: 'new-sdo' },
    },
  };
};

export default convertHuntToStix;
