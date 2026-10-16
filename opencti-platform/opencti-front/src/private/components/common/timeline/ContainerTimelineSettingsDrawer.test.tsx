import React from 'react';
import { describe, expect, it, vi } from 'vitest';
import { screen, within } from '@testing-library/react';
import testRender, { createMockUserContext } from '../../../../utils/tests/test-render';
import ContainerTimelineSettingsDrawer from './ContainerTimelineSettingsDrawer';

const settings = { enabled_lanes: ['adversary', 'response'], default_grouping: 'day', default_zoom_window: 'fit', hidden_kinds: [] };

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
