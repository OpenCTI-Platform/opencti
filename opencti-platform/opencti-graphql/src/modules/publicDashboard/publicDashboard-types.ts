import type { BasicStoreEntity, StoreEntity, StoreMarkingDefinition } from '../../types/store';
import type { StixDomainObject, StixOpenctiExtensionSDO } from '../../types/stix-common';
import { STIX_EXT_OCTI } from '../../types/stix-extensions';
import type { AuthorizedMember } from '../../utils/access';
import type { FilterGroup } from '../../generated/graphql';

export const ENTITY_TYPE_PUBLIC_DASHBOARD = 'PublicDashboard';

// region Database types
export interface BasicStoreEntityPublicDashboard extends BasicStoreEntity {
  name: string;
  description: string;
  dashboard_id: string;
  user_id: string;
  public_manifest: string;
  private_manifest: string;
  uri_key: string;
  authorized_members: Array<AuthorizedMember>;
  allowed_markings_ids: Array<string>;
  allowed_markings: Array<StoreMarkingDefinition>;
}

export interface StoreEntityPublicDashboard extends StoreEntity {
  name: string;
  description: string;
  dashboard_id: string;
  user_id: string;
  public_manifest: string;
  private_manifest: string;
  uri_key: string;
  authorized_members: Array<AuthorizedMember>;
  allowed_markings_ids: Array<string>;
  allowed_markings: Array<StoreMarkingDefinition>;
}
// endregion

// region cache type
export interface PublicDashboardCachedWidget {
  id: string
  perspective: 'entities' | 'relationships' | 'audits' | null
  type: string,
  layout: {
    w: number
    h: number,
    x: number
    y: number
    i: string
    moved: boolean
    static: boolean
  }
  parameters: {
    title?: string
    interval?: string
    stacked?: boolean
    legend?: boolean
    distributed?: boolean
  }
  dataSelection: {
    filters?: FilterGroup
    dynamicFrom?: FilterGroup
    dynamicTo?: FilterGroup
    label?: string
    attribute?: string
    date_attribute?: string
    centerLat?: number
    centerLng?: number
    zoom?: number
    isTo?: boolean
    number?: boolean
    toTypes?: string[]
    perspective?: 'entities' | 'relationships' | 'audits' | null
  }[]
}

export interface PublicDashboardCached {
  id: string;
  internal_id: string;
  uri_key: string;
  dashboard_id: string;
  private_manifest: {
    widgets: Record<string, PublicDashboardCachedWidget>,
    config: {
      startDate?: string
      endDate?: string
      relativeDate?: string
    }
  };
  user_id: string;
  allowed_markings_ids: string[];
  allowed_markings: Array<StoreMarkingDefinition>;
}
// endregion

// region Stix type
export interface StixPublicDashboard extends StixDomainObject {
  name: string;
  description: string;
  dashboard_id: string;
  user_id: string;
  public_manifest: string;
  private_manifest: string;
  uri_key: string;
  allowed_markings_ids: Array<string>;
  allowed_markings: Array<StoreMarkingDefinition>;
  extensions: {
    [STIX_EXT_OCTI] : StixOpenctiExtensionSDO
  };
}
// endregion
