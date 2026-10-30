import React from 'react';
import { describe, expect, it } from 'vitest';
import { act, screen } from '@testing-library/react';
import { MockPayloadGenerator } from 'relay-test-utils';
import testRender from '../../../../../utils/tests/test-render';
import ConfigPresetExportFooter from './ConfigPresetExportFooter';

describe('ConfigPresetExportFooter', () => {
  it('keeps the card footer actions above the export button', () => {
    testRender(
      <ConfigPresetExportFooter>
        <button type="button">Update license</button>
      </ConfigPresetExportFooter>,
    );
    const cardAction = screen.getByRole('button', { name: 'Update license' });
    const exportButton = screen.getByRole('button', { name: 'Export Bootstrap Platform Bundle' });
    expect(cardAction.compareDocumentPosition(exportButton) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    expect(screen.getByRole('separator')).toBeInTheDocument();
  });

  it('shows only the export button when the card has no footer actions', () => {
    testRender(<ConfigPresetExportFooter />);
    expect(screen.getByRole('button', { name: 'Export Bootstrap Platform Bundle' })).toBeInTheDocument();
    expect(screen.queryByRole('separator')).not.toBeInTheDocument();
  });

  it('opens the Platform Bundle drawer and loads the exportable types on click', async () => {
    const { user, relayEnv } = testRender(<ConfigPresetExportFooter />);
    expect(relayEnv.mock.getAllOperations()).toHaveLength(0);

    await user.click(screen.getByRole('button', { name: 'Export Bootstrap Platform Bundle' }));
    await act(async () => {
      relayEnv.mock.resolveMostRecentOperation((operation) => MockPayloadGenerator.generate(operation, {
        Query: () => ({
          configPresetExportableTypes: [{
            key: 'messages',
            label: 'Messages',
            description: 'Banner, login and consent messages',
            group: { key: 'platformSettings', label: 'Platform settings' },
            requiresEnterpriseEdition: false,
            locked: false,
            items: [{ key: 'messages', label: 'Messages', translatable: true, isDefault: false, dependsOn: [] }],
            itemsPageInfo: { hasNextPage: false, globalCount: 1 },
          }],
        }),
      }));
    });
    expect(await screen.findByText('Platform Bundle')).toBeInTheDocument();
    expect(screen.getByRole('checkbox', { name: 'Platform settings (1/1)' })).toBeInTheDocument();
    expect(screen.getByRole('checkbox', { name: 'Messages' })).toBeInTheDocument();
  });

  it('opens the import wizard in manual mode and closes it without writing anything', async () => {
    const { user, relayEnv } = testRender(<ConfigPresetExportFooter />);
    await user.click(screen.getByRole('button', { name: 'Import Bootstrap Platform Bundle' }));
    expect(screen.getByText('Quick Start - Platform Setup')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Close' }));
    expect(screen.queryByText('Quick Start - Platform Setup')).not.toBeInTheDocument();
    // Nothing is written: only the import session was read
    expect(relayEnv.mock.getAllOperations().map((operation) => operation.request.node.operation.name)).not.toContain('ConfigPresetWizardSkipMutation');
  });
});
