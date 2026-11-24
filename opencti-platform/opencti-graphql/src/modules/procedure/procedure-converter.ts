import { buildKillChainPhases, buildStixDomain } from '../../database/stix-2-1-converter';
import { STIX_EXT_OCTI } from '../../types/stix-2-1-extensions';
import { cleanObject, convertToStixDate } from '../../database/stix-converter-utils';
import type { StixDate } from '../../types/stix-2-1-common';
import { ATTRIBUTE_COMMAND_REF, ATTRIBUTE_SOURCE_REFS, INPUT_PROCEDURE_COMMAND, INPUT_PROCEDURE_SOURCES, type StixProcedure, type StoreEntityProcedure } from './procedure-types';

const convertProcedureToStix = (instance: StoreEntityProcedure): StixProcedure => {
  const stixDomainObject = buildStixDomain(instance);
  return {
    ...stixDomainObject,
    name: instance.name,
    description: instance.description,
    x_procedure_type: instance.x_procedure_type,
    platforms: instance.x_mitre_platforms,
    kill_chain_phases: buildKillChainPhases(instance),
    [ATTRIBUTE_COMMAND_REF]: instance[INPUT_PROCEDURE_COMMAND]?.standard_id,
    [ATTRIBUTE_SOURCE_REFS]: (instance[INPUT_PROCEDURE_SOURCES] ?? []).map((s) => s.standard_id),
    first_observed: convertToStixDate(instance.first_observed) as StixDate,
    last_observed: convertToStixDate(instance.last_observed) as StixDate,
    x_execution_start: convertToStixDate(instance.x_execution_start) as StixDate,
    x_execution_end: convertToStixDate(instance.x_execution_end) as StixDate,
    x_fingerprint: instance.x_fingerprint,
    extensions: {
      [STIX_EXT_OCTI]: cleanObject({
        ...stixDomainObject.extensions[STIX_EXT_OCTI],
        extension_type: 'new-sdo',
      }),
    },
  };
};

export default convertProcedureToStix;
