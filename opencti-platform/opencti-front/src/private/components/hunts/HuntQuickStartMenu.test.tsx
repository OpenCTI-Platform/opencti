import React from 'react';
import { describe, expect, it } from 'vitest';
import { screen } from '@testing-library/react';
import testRender, { createMockUserContext } from '../../../utils/tests/test-render';
import HuntQuickStartMenu from './HuntQuickStartMenu';
import { HuntPackImportButton } from './HuntPack';

const hubSettings = { id: 'platform-id', platform_xtmhub_url: 'https://hub.filigran.io' };

describe('HuntQuickStartMenu', () => {
  it('offers no XTM Hub entry among the quick starts, even when the hub is reachable', async () => {
    const { user } = testRender(<HuntQuickStartMenu />, { userContext: createMockUserContext({ settings: hubSettings }) });
    await user.click(screen.getByTestId('hunts-quick-start'));
    expect(await screen.findByTestId('hunts-quick-start-indicators')).toBeInTheDocument();
    expect(screen.queryByTestId('hunts-quick-start-hub')).toBeNull();
    expect(screen.queryByText('Import from XTM Hub')).toBeNull();
  });
});

describe('HuntPackImportButton', () => {
  it('imports a hunt pack file with no XTM Hub link next to it', () => {
    testRender(<HuntPackImportButton paginationOptions={{}} />, { userContext: createMockUserContext({ settings: hubSettings }) });
    expect(screen.getByTestId('hunt-pack-import')).toBeInTheDocument();
    expect(screen.queryByRole('link', { name: 'Import from XTM Hub' })).toBeNull();
  });
});
