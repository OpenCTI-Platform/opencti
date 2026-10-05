import React from 'react';
import { describe, expect, it } from 'vitest';
import { screen } from '@testing-library/react';
import testRender, { createMockUserContext } from '../../../utils/tests/test-render';
import HuntQuickStartMenu from './HuntQuickStartMenu';
import { HuntPackImportButton } from './HuntPack';

const hubSettings = { id: 'platform-id', platform_xtmhub_url: 'https://hub.filigran.io' };
const hubUrl = 'https://hub.filigran.io/redirect/opencti_hunt_packs?platform_id=platform-id';

describe('HuntQuickStartMenu', () => {
  it('offers the hunt packs of the XTM Hub among the quick starts', async () => {
    const { user } = testRender(<HuntQuickStartMenu />, { userContext: createMockUserContext({ settings: hubSettings }) });
    await user.click(screen.getByTestId('hunts-quick-start'));
    expect(await screen.findByTestId('hunts-quick-start-hub')).toHaveTextContent('Import from XTM Hub');
  });

  it('offers no XTM Hub entry when the hub is not reachable', async () => {
    const userContext = { ...createMockUserContext({ settings: hubSettings }), isXTMHubAccessible: false };
    const { user } = testRender(<HuntQuickStartMenu />, { userContext });
    await user.click(screen.getByTestId('hunts-quick-start'));
    expect(await screen.findByTestId('hunts-quick-start-indicators')).toBeInTheDocument();
    expect(screen.queryByTestId('hunts-quick-start-hub')).toBeNull();
  });
});

describe('HuntPackImportButton', () => {
  it('links to the hunt packs of the XTM Hub on the first-use page', () => {
    testRender(<HuntPackImportButton paginationOptions={{}} />, { userContext: createMockUserContext({ settings: hubSettings }) });
    expect(screen.getByRole('link', { name: 'Import from XTM Hub' })).toHaveAttribute('href', hubUrl);
  });

  it('leaves the XTM Hub link to the Quick start menu in the toolbar of the list', () => {
    testRender(<HuntPackImportButton paginationOptions={{}} showHubLink={false} />, { userContext: createMockUserContext({ settings: hubSettings }) });
    expect(screen.getByTestId('hunt-pack-import')).toBeInTheDocument();
    expect(screen.queryByRole('link', { name: 'Import from XTM Hub' })).toBeNull();
  });
});
