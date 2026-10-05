import type { StixObject, StixOpenctiExtensionSDO } from '../../../types/stix-2-1-common';
import { STIX_EXT_OCTI } from '../../../types/stix-2-1-extensions';
import type { BasicStoreEntity, StoreEntity } from '../../../types/store';
import type { IndicatorRuleLogsource } from '../../indicator/indicator-types';

export const ENTITY_TYPE_DEFENSE_LOGSOURCE_MAPPING = 'DefenseLogsourceMapping';

export interface DefenseLogsourceMappingDefault {
  logsource_category?: string;
  logsource_product?: string;
  logsource_service?: string;
  data_components: string[];
  description?: string;
}

interface DefenseLogsourceMappingFields {
  name: string;
  mapping_key: string;
  x_opencti_rule_logsource?: IndicatorRuleLogsource;
  data_components: string[];
  active: boolean;
  built_in: boolean;
}

export interface BasicStoreEntityDefenseLogsourceMapping extends BasicStoreEntity, DefenseLogsourceMappingFields {}

export interface StoreEntityDefenseLogsourceMapping extends StoreEntity, DefenseLogsourceMappingFields {}

export interface StixDefenseLogsourceMapping extends StixObject {
  name: string;
  description?: string;
  logsource_category?: string;
  logsource_product?: string;
  logsource_service?: string;
  data_components: string[];
  active: boolean;
  extensions: {
    [STIX_EXT_OCTI]: StixOpenctiExtensionSDO;
  };
}
