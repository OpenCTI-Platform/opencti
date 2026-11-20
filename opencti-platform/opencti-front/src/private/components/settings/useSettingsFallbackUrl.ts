import useFirstVisiblePath from '../common/menus/useFirstVisiblePath';
import { sectionEntries } from '../nav/navSections';

const settingsEntries = sectionEntries('settings');

/**
 * Where to send a user who cannot open a Settings page: the first Settings page they can open (same rules as the left
 * bar), or the home page when there is none (no Settings capability, or a draft, where Settings is closed).
 */
const useSettingsFallbackUrl = (): string => useFirstVisiblePath(settingsEntries);

export default useSettingsFallbackUrl;
