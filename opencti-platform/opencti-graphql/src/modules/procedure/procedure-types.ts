import type { BasicStoreEntity, StoreEntity } from '../../types/store';
import type { StixDate, StixDomainObject, StixId, StixOpenctiExtensionSDO } from '../../types/stix-2-1-common';
import type { StixInternalKillChainPhase } from '../../types/stix-2-1-smo';
import { STIX_EXT_OCTI } from '../../types/stix-2-1-extensions';

export const ENTITY_TYPE_PROCEDURE = 'Procedure';
export const STIX_TYPE_PROCEDURE = 'x-opencti-procedure';

// region Refs
// Observables are has-observable relationships; the input keeps this name and creates them.
export const INPUT_PROCEDURE_OBSERVABLES = 'procedureObservables';

export const INPUT_PROCEDURE_COMMAND = 'procedureCommand';
export const RELATION_PROCEDURE_COMMAND = 'procedure-command';
export const ATTRIBUTE_COMMAND_REF = 'x_command_ref';

export const INPUT_PROCEDURE_SOURCES = 'procedureSources';
export const RELATION_PROCEDURE_SOURCE = 'procedure-source';
export const ATTRIBUTE_SOURCE_REFS = 'x_source_refs';
// endregion

// region Database types
export interface BasicStoreEntityProcedure extends BasicStoreEntity {
  name: string;
  description: string;
  x_procedure_type: string;
  x_mitre_platforms: Array<string>;
  first_observed: Date;
  last_observed: Date;
  x_execution_start: Date;
  x_execution_end: Date;
  x_fingerprint: string;
  [RELATION_PROCEDURE_COMMAND]: string;
  [RELATION_PROCEDURE_SOURCE]: Array<string>;
}

export interface StoreEntityProcedure extends StoreEntity {
  name: string;
  description: string;
  x_procedure_type: string;
  x_mitre_platforms: Array<string>;
  first_observed: Date;
  last_observed: Date;
  x_execution_start: Date;
  x_execution_end: Date;
  x_fingerprint: string;
  [INPUT_PROCEDURE_COMMAND]: BasicStoreEntity;
  [INPUT_PROCEDURE_SOURCES]: Array<BasicStoreEntity>;
}
// endregion

// region Stix type
export interface StixProcedure extends StixDomainObject {
  name: string;
  description: string;
  x_procedure_type: string;
  platforms: Array<string>;
  kill_chain_phases: Array<StixInternalKillChainPhase>;
  [ATTRIBUTE_COMMAND_REF]: StixId | undefined;
  [ATTRIBUTE_SOURCE_REFS]: Array<StixId>;
  first_observed: StixDate;
  last_observed: StixDate;
  x_execution_start: StixDate;
  x_execution_end: StixDate;
  x_fingerprint: string;
  extensions: {
    [STIX_EXT_OCTI]: StixOpenctiExtensionSDO;
  };
}
// endregion
