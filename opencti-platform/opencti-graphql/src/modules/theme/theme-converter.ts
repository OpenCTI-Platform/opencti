import { buildStixDomain, cleanObject } from '../../database/stix-converter';
import { STIX_EXT_OCTI } from '../../types/stix-extensions';
import type { StixTheme, StoreEntityTheme } from './theme-types';

const convertThemeToStix = (instance: StoreEntityTheme): StixTheme => {
  const stixDomainObject = buildStixDomain(instance);
  return {
    ...stixDomainObject,
    name: instance.name,
    theme_background: instance.theme_background,
    theme_paper: instance.theme_paper,
    theme_nav: instance.theme_nav,
    theme_primary: instance.theme_primary,
    theme_secondary: instance.theme_secondary,
    theme_accent: instance.theme_accent,
    theme_logo: instance.theme_logo,
    theme_logo_collapsed: instance.theme_logo_collapsed,
    theme_logo_login: instance.theme_logo_login,
    extensions: {
      [STIX_EXT_OCTI]: cleanObject({
        ...stixDomainObject.extensions[STIX_EXT_OCTI],
        extension_type: 'new-sdo',
      })
    },
  };
};

export default convertThemeToStix;
