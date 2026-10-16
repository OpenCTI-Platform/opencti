import React from 'react';
import { describe, expect, it, vi } from 'vitest';
import { screen, within } from '@testing-library/react';
import testRender, { createMockUserContext } from '../../../../utils/tests/test-render';
import ContainerTimelineSettingsDrawer from './ContainerTimelineSettingsDrawer';

const settings = { enabled_lanes: ['adversary', 'response'], hidden_kinds: [] };

const renderDrawer = (capabilities: string[]) => testRender(
  <ContainerTimelineSettingsDrawer
    containerId="case-1"
    entityType="Case-Incident"
    headlineDates={['containment', 'recovery']}
    open={true}
    settings={settings}
    onClose={vi.fn()}
    onSaved={vi.fn()}
  />,
  { userContext: createMockUserContext({ me: { id: 'user-1', capabilities: capabilities.map((name) => ({ name })) } }) },
);

describe('ContainerTimelineSettingsDrawer headline dates', () => {
  it('shows the headline dates of the type read-only, with a link to their customization', async () => {
    renderDrawer(['SETTINGS_SETCUSTOMIZATION']);
    const section = await screen.findByTestId('timeline-settings-headline-dates');
    expect(within(section).getAllByRole('listitem').map((item) => item.textContent)).toEqual(['Containment', 'Recovery']);
    expect(within(section).queryByRole('checkbox')).toBeNull();
    expect(within(section).getByTestId('timeline-settings-headline-dates-link'))
      .toHaveAttribute('href', '/dashboard/settings/customization/entity_types/Case-Incident/timeline');
  });

  it('names them without a link for users who cannot customize the types', async () => {
    renderDrawer(['KNOWLEDGE_KNUPDATE']);
    const section = await screen.findByTestId('timeline-settings-headline-dates');
    expect(within(section).getAllByRole('listitem')).toHaveLength(2);
    expect(within(section).queryByRole('link')).toBeNull();
  });
});

describe('ContainerTimelineSettingsDrawer display choices', () => {
  it('leaves the zoom, the grouping and the view to each reader', async () => {
    const { user, relayEnv } = renderDrawer(['KNOWLEDGE_KNUPDATE']);
    const drawer = await screen.findByTestId('timeline-settings-drawer');
    expect(drawer).toHaveTextContent('The zoom, the grouping and the view are kept for each reader, in their browser.');
    expect(within(drawer).queryByRole('combobox')).toBeNull();
    await user.click(screen.getByTestId('timeline-settings-save'));
    expect(relayEnv.mock.getMostRecentOperation().request.variables).toEqual({
      containerId: 'case-1',
      input: { enabled_lanes: ['adversary', 'response'], hidden_kinds: [] },
    });
  });
});
