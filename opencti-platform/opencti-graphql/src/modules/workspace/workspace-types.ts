import type { BasicStoreEntity, StoreEntity } from '../../types/store';
import type { StixDomainObject, StixOpenctiExtensionSDO } from '../../types/stix-2-1-common';
import { STIX_EXT_OCTI } from '../../types/stix-2-1-extensions';
import type { AuthorizedMember } from '../../utils/access';
import { DashboardFilterKeyType } from '../../generated/graphql';

export { DashboardFilterKeyType };

export const ENTITY_TYPE_WORKSPACE = 'Workspace';

// region Dashboard variable / manifest types
export interface DashboardVariable {
  id: string;
  name: string;
  filterKey: string;
  filterKeyType: DashboardFilterKeyType;
  defaultValue: string | null;
  /** Semantics depend on filterKeyType: entity_ref -> 'none' | 'filter' | 'manual'; others -> 'none' | 'restricted' */
  restrictionMode?: string | null;
  /** Allowed values (ids/names) when restrictionMode restricts the selectable options */
  restrictionValues?: string[] | null;
  /** Serialised FilterGroup JSON, only used for entity_ref 'filter' restriction mode */
  restrictionFilters?: string | null;
}

export interface DashboardPreset {
  id: string;
  name: string;
  /** Serialised JSON: Record<variableId, value> */
  variable_values: string;
}

export interface DashboardManifest {
  widgets?: Record<string, unknown>;
  variables?: DashboardVariable[];
  presets?: DashboardPreset[];
}
// endregion

// region Database types
export interface BasicStoreEntityWorkspace extends BasicStoreEntity {
  name: string;
  description: string;
  graph_data: string;
  manifest: string;
  refresh_interval?: number | null;
  tags: Array<string>;
  type: string;
  restricted_members: Array<AuthorizedMember>;
  object_refs: Array<string>;
  investigated_entities_ids: Array<string>;
}

export interface StoreEntityWorkspace extends StoreEntity {
  name: string;
  description: string;
  graph_data: string;
  manifest: string;
  refresh_interval?: number | null;
  tags: Array<string>;
  type: string;
  restricted_members: Array<AuthorizedMember>;
  object_refs: Array<string>;
  investigated_entities_ids: Array<string>;
}
// endregion

// region Stix type
export interface StixWorkspace extends StixDomainObject {
  name: string;
  description: string;
  graph_data: string;
  manifest: string;
  tags: Array<string>;
  type: string;
  object_refs: Array<string>;
  aliases: Array<string>;
  extensions: {
    [STIX_EXT_OCTI]: StixOpenctiExtensionSDO;
  };
}
// endregion
