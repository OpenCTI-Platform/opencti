import { describe, expect, it, vi } from 'vitest';
import { testRenderHook } from '../../../utils/tests/test-render';
import useNavSearch from './useNavSearch';
import { allMenuEntries } from './menuEntries';
import type { NavGroup, NavSubItem } from './useNavMenu';

let subItems: NavSubItem[] = [];
vi.mock('./useNavMenu', () => ({
  default: (): NavGroup[] => [
    { id: 'main', items: [{ id: 'home', label: 'Home', icon: null, link: '/dashboard', exact: true, keywords: ['cockpit'] }] },
    { id: 'settings', items: [{ id: 'settings', label: 'Settings', icon: null, link: '/dashboard/settings', subItems }] },
  ],
}));
// The real gate (useVisibleEntries) runs, with a BYPASS user unless a test says otherwise: it passes every capability rule.
let capabilities = ['BYPASS'];
vi.mock('../../../utils/hooks/useAuth', async (importOriginal) => ({
  ...(await importOriginal<object>()),
  default: () => ({ me: { draftContext: null, capabilities: capabilities.map((name) => ({ name })), capabilitiesInDraft: [] } }),
}));
vi.mock('../../../utils/hooks/useHelper', () => ({ default: () => ({ isTrashEnable: () => true, isFeatureEnable: () => true }) }));
vi.mock('../../../utils/hooks/useEnterpriseEdition', () => ({ default: () => true }));
vi.mock('../../../utils/hooks/useEntitySettings', () => ({ useHiddenEntities: () => [] }));

const search = (keyword: string) => testRenderHook(() => useNavSearch(keyword)).hook.result.current.map(({ path }) => path);

describe('Hook: useNavSearch', () => {
  const parameters = { link: '/dashboard/settings', label: 'Parameters', exact: true };
  // A sub-section row as the left bar builds it: covers the declared pages under its prefix.
  const section = (link: string, label: string): NavSubItem => ({
    link,
    label,
    paths: allMenuEntries.map(({ path }) => path).filter((path) => path.startsWith(`${link}/`)),
  });
  const customization = section('/dashboard/settings/customization', 'Customization');
  const taxonomies = section('/dashboard/settings/vocabularies', 'Taxonomies');

  it('indexes an entry whose subsection is visible, with the subsection in the breadcrumb', () => {
    subItems = [parameters, customization];
    const { hook } = testRenderHook(() => useNavSearch('retention'));
    expect(hook.result.current).toEqual([
      { path: '/dashboard/settings/customization/retention', label: 'Retention policies', parents: ['Settings', 'Customization'] },
    ]);
  });

  it('drops an entry when its subsection is hidden, even if a broader parent is visible', () => {
    // A Customization-only user: the Taxonomies subsection (and its /vocabularies/* route) is out of reach.
    subItems = [parameters, customization];
    const customFields = '/dashboard/settings/vocabularies/custom_fields';
    expect(search('custom fields')).not.toContain(customFields);
    subItems = [parameters, customization, taxonomies];
    expect(search('custom fields')).toContain(customFields);
  });

  it('indexes top bar pages without any left bar subsection', () => {
    subItems = [];
    expect(search('triggers')).toContain('/dashboard/profile/notifications/triggers');
    expect(search('notification')).toContain('/dashboard/profile/notifications');
    expect(search('profile')).toContain('/dashboard/profile/me');
  });

  it('ignores case and accents, both in the keyword and in the (translated) labels', () => {
    subItems = [parameters, { link: '/dashboard/settings/config', label: 'Paramètres avancés' }];
    expect(search('PARAMETRES avances')).toContain('/dashboard/settings/config');
    expect(search('paramètres')).toContain('/dashboard/settings/config');
  });

  it('matches the beginning of a word only, not any substring', () => {
    subItems = [parameters, customization];
    const retention = '/dashboard/settings/customization/retention';
    expect(search('ret')).toContain(retention);
    expect(search('POLI')).toContain(retention);
    expect(search('tention')).not.toContain(retention);
    expect(search('olicies')).not.toContain(retention);
  });

  it('tests each typed word on its own, in any order', () => {
    subItems = [parameters, customization];
    const retention = '/dashboard/settings/customization/retention';
    expect(search('pol ret')).toContain(retention);
    expect(search('ret pol')).toContain(retention);
    expect(search('ret xyz')).not.toContain(retention);
    // A word of the breadcrumb counts too.
    expect(search('custom ret')).toContain(retention);
  });

  it('keeps "&" inside a word, so "c&c" is not the two words "c" and "c"', () => {
    subItems = [{ link: '/dashboard/c2', label: 'Servers', keywords: ['c&c'] }];
    // Home has the keyword "cockpit": it would match if "c&c" were split.
    expect(search('c&c')).toEqual(['/dashboard/c2']);
    expect(search('c&')).toEqual(['/dashboard/c2']);
  });

  it('also searches the English label when the user language is not English', () => {
    subItems = [parameters, { link: '/dashboard/settings/config', label: 'Paramètres avancés', englishLabel: 'Advanced parameters' }];
    expect(search('adv param')).toContain('/dashboard/settings/config');
    expect(search('param avan')).toContain('/dashboard/settings/config');
  });

  it('matches an entry keyword whatever the case of the keyword and of the typed text', () => {
    // Keywords reuse the casing of the existing translation keys ('2FA', 'SSO'...).
    subItems = [section('/dashboard/settings/accesses', 'Security')];
    ['2fa', '2FA'].forEach((typed) => expect(search(typed)).toContain('/dashboard/profile/me'));
    ['sso', 'SSO'].forEach((typed) => expect(search(typed)).toContain('/dashboard/settings/accesses/authentications'));
  });

  it('hints the keyword that matched when neither the label nor the breadcrumb say why', () => {
    subItems = [{ link: '/dashboard/x', label: 'Parameters', keywords: ['themes', 'Dependencies'] }];
    const hints = (keyword: string) => testRenderHook(() => useNavSearch(keyword)).hook.result.current
      .find(({ path }) => path === '/dashboard/x')?.hints;
    // Lower case, whatever the casing of the keyword ('Dependencies').
    expect(hints('the')).toEqual(['themes']);
    expect(hints('DEPEND')).toEqual(['dependencies']);
    // The label says it: no hint.
    expect(hints('param')).toBeUndefined();
    // One hint per typed word that only a keyword explains.
    expect(hints('param the')).toEqual(['themes']);
  });

  it('hints the word of the language typed, with its accents', () => {
    // Keyword translated as in a French UI, the English one stays searchable too.
    subItems = [{ link: '/dashboard/x', label: 'Réglages', keywords: ['thème', 'theme'] }];
    const hints = (keyword: string) => testRenderHook(() => useNavSearch(keyword)).hook.result.current
      .find(({ path }) => path === '/dashboard/x')?.hints;
    expect(hints('the')).toEqual(['thème']);
    expect(hints('thè')).toEqual(['thème']);
  });

  it('hints the English label word when it is the English label that matched', () => {
    subItems = [{ link: '/dashboard/x', label: 'Paramètres avancés', englishLabel: 'Advanced parameters' }];
    const hints = (keyword: string) => testRenderHook(() => useNavSearch(keyword)).hook.result.current
      .find(({ path }) => path === '/dashboard/x')?.hints;
    expect(hints('adv')).toEqual(['advanced']);
    // Matched in the displayed label too: no hint.
    expect(hints('param')).toBeUndefined();
    expect(hints('param adv')).toEqual(['advanced']);
  });

  it('does not return a page whose capability the user is missing', () => {
    subItems = [parameters, customization];
    const retention = '/dashboard/settings/customization/retention';
    try {
      capabilities = ['SETTINGS_SETCUSTOMIZATION'];
      expect(search('retention')).toContain(retention);
      capabilities = ['SETTINGS_SETLABELS'];
      expect(search('retention')).not.toContain(retention);
    } finally {
      capabilities = ['BYPASS'];
    }
  });

  it('finds the Home page', () => {
    subItems = [];
    expect(search('home')).toEqual(['/dashboard']);
  });

  it('matches the keywords of a top-level page that has no subsection', () => {
    subItems = [];
    expect(search('cockpit')).toEqual(['/dashboard']);
  });

  it('drops Import entries when the Import subsection is hidden (draft)', () => {
    subItems = [];
    expect(search('drafts')).toEqual([]);
  });
});
