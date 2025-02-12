import type { StixObject, StixOpenctiExtensionSDO } from '../../types/stix-common';
import type { STIX_EXT_OCTI } from '../../types/stix-extensions';
import type { BasicStoreEntity, StoreEntity } from '../../types/store';

// region Database types
export interface BasicStoreEntityTheme extends BasicStoreEntity {
  name: string;
  theme_background: string;
  theme_paper: string;
  theme_nav: string;
  theme_primary: string;
  theme_secondary: string;
  theme_accent: string;
  theme_logo: string;
  theme_logo_collapsed: string;
  theme_logo_login: string;
}

export interface StoreEntityTheme extends StoreEntity {
  name: string;
  theme_background: string;
  theme_paper: string;
  theme_nav: string;
  theme_primary: string;
  theme_secondary: string;
  theme_accent: string;
  theme_logo: string;
  theme_logo_collapsed: string;
  theme_logo_login: string;
}
// endregion

// region Stix type
export interface StixTheme extends StixObject {
  name: string;
  theme_background: string;
  theme_paper: string;
  theme_nav: string;
  theme_primary: string;
  theme_secondary: string;
  theme_accent: string;
  theme_logo: string;
  theme_logo_collapsed: string;
  theme_logo_login: string;
  extensions: {
    [STIX_EXT_OCTI]: StixOpenctiExtensionSDO
  };
}
// endregion
