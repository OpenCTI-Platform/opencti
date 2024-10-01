import { fromB64, toB64 } from '../../../../utils/String';
import { isEmptyField } from '../../../../utils/utils';

type ThemeManifestType = {
  theme_background: string,
  theme_paper: string,
  theme_nav: string,
  theme_primary: string,
  theme_secondary: string,
  theme_accent: string,
  theme_logo: string | null,
  theme_logo_collapsed: string | null,
  theme_logo_login: string | null,
  system_default: boolean | null,
};

interface ThemeType extends ThemeManifestType {
  id: string,
  name: string,
}

/**
 * Serializes a theme into the backend-compatible manifest type. Base64 encoded.
 * @param theme ThemeManifestType to convert into a manifest string
 */
export const serializeThemeManifest = (theme: ThemeManifestType): string => {
  return toB64(JSON.stringify(theme));
};

/**
 * Deserializes a base64-encoded manifest string into a ThemeManifestType.
 * @param manifest Base64-encoded manifest string
 */
export const deserializeThemeManifest = (
  manifest: string | undefined | null,
): ThemeManifestType => {
  const b64decoded = fromB64(manifest ?? '');
  return JSON.parse(isEmptyField(b64decoded) ? '{}' : b64decoded);
};

export default ThemeType;
