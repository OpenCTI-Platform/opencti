import React from 'react';
import { describe, expect, it, vi } from 'vitest';
import { screen } from '@testing-library/react';
import testRender from '../../../utils/tests/test-render';
import EntryGuard from './EntryGuard';

let capabilities: string[] = [];
let draftContext: { id: string } | null = null;
let flagOn = true;
let enterpriseEdition = true;
let hiddenEntities: string[] = [];
vi.mock('../../../utils/hooks/useAuth', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../utils/hooks/useAuth')>()),
  default: () => ({ me: { capabilities: capabilities.map((name) => ({ name })), capabilitiesInDraft: [], draftContext } }),
}));
vi.mock('../../../utils/hooks/useHelper', () => ({ default: () => ({ isFeatureEnable: () => flagOn }) }));
vi.mock('../../../utils/hooks/useEnterpriseEdition', () => ({ default: () => enterpriseEdition }));
vi.mock('../../../utils/hooks/useEntitySettings', () => ({ useHiddenEntities: () => hiddenEntities }));

// Real entries: the guard must follow what the pages declare.
const open = (path: string, exact = false) => {
  const { unmount } = testRender(
    <EntryGuard path={path} exact={exact} placeholder={<span>redirected</span>}><span>page</span></EntryGuard>,
  );
  const shown = screen.queryByText('page') !== null;
  unmount();
  return shown;
};
const reset = () => {
  capabilities = [];
  draftContext = null;
  flagOn = true;
  enterpriseEdition = true;
  hiddenEntities = [];
};

describe('Component: EntryGuard', () => {
  it('opens a page to a user with one of its capabilities, and closes it to the others', () => {
    reset();
    capabilities = ['SETTINGS_SETCUSTOMIZATION'];
    expect(open('/dashboard/settings/customization/rules')).toBe(true);
    capabilities = ['SETTINGS_SETLABELS'];
    expect(open('/dashboard/settings/customization/rules')).toBe(false);
  });

  it('opens a section when one of its pages is open', () => {
    reset();
    capabilities = ['SETTINGS_SETLABELS'];
    expect(open('/dashboard/settings/vocabularies')).toBe(true);
    expect(open('/dashboard/settings/vocabularies/kill_chain_phases')).toBe(false);
  });

  it('with `exact`, only looks at the page itself, not at the pages under it', () => {
    reset();
    capabilities = ['SETTINGS_SETCUSTOMIZATION'];
    expect(open('/dashboard/settings', true)).toBe(false);
    capabilities = ['SETTINGS_SETPARAMETERS'];
    expect(open('/dashboard/settings', true)).toBe(true);
  });

  it('closes a page whose feature flag is off', () => {
    reset();
    capabilities = ['BYPASS'];
    expect(open('/dashboard/data/health')).toBe(true);
    flagOn = false;
    expect(open('/dashboard/data/health')).toBe(false);
  });

  it('closes a page that needs the Enterprise Edition', () => {
    reset();
    capabilities = ['BYPASS'];
    expect(open('/dashboard/data/restriction/restricted')).toBe(true);
    enterpriseEdition = false;
    expect(open('/dashboard/data/restriction/restricted')).toBe(false);
  });

  it('closes a page that is not available in a draft, even for a user with the capability', () => {
    reset();
    capabilities = ['SETTINGS_SETCUSTOMIZATION'];
    draftContext = { id: 'draft-id' };
    expect(open('/dashboard/settings/customization/rules')).toBe(false);
  });

  it('closes Filigran Experience in a draft, even for an administrator', () => {
    reset();
    capabilities = ['BYPASS'];
    expect(open('/dashboard/settings/experience')).toBe(true);
    draftContext = { id: 'draft-id' };
    expect(open('/dashboard/settings/experience')).toBe(false);
  });

  it('keeps open a page whose entity type is hidden: hiding declutters the menus, it does not deny access', () => {
    reset();
    capabilities = ['KNOWLEDGE'];
    hiddenEntities = ['Malware'];
    expect(open('/dashboard/arsenal/malwares')).toBe(true);
  });

  it('denies a path no page declares', () => {
    reset();
    capabilities = ['BYPASS'];
    expect(open('/dashboard/nope')).toBe(false);
  });
});
