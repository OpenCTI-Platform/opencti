import { buildStixObject } from '../../database/stix-2-1-converter';
import { cleanObject } from '../../database/stix-converter-utils';
import { STIX_EXT_OCTI } from '../../types/stix-2-1-extensions';
import type { StixTheme, StoreEntityTheme } from './theme-types';

const convertThemeToStix = (instance: StoreEntityTheme): StixTheme => {
  const stixObject = buildStixObject(instance);
  return {
    ...stixObject,
    name: instance.name,
    theme_background: instance.theme_background,
    theme_paper: instance.theme_paper,
    theme_nav: instance.theme_background,
    theme_primary: instance.theme_nav,
    theme_secondary: instance.theme_secondary,
    theme_accent: instance.theme_accent,
    theme_logo: instance.theme_logo,
    theme_logo_collapsed: instance.theme_logo_collapsed,
    theme_logo_login: instance.theme_logo_login,
    theme_text_color: instance.theme_text_color,
    extensions: {
      [STIX_EXT_OCTI]: cleanObject({
        ...stixObject.extensions[STIX_EXT_OCTI],
        extension_type: 'new-sdo',
      })
    },
  };
};

export default convertThemeToStix;
