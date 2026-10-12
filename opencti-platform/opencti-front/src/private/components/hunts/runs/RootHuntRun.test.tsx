import React from 'react';
import { describe, expect, it, vi } from 'vitest';
import { act, screen, within } from '@testing-library/react';
import { Route, Routes } from 'react-router';
import { MockPayloadGenerator } from 'relay-test-utils';
import testRender, { createMockUserContext } from '../../../../utils/tests/test-render';
import { BYPASS } from '../../../../utils/hooks/useGranted';
import RootHuntRun from './RootHuntRun';

vi.mock('./HuntRun', () => ({
  default: ({ title, canEdit }: { title: string; canEdit: boolean }) => (
    <div data-testid="hunt-run-body" data-can-edit={String(canEdit)}>{title}</div>
  ),
}));

const renderRunPage = async (resolvers: Parameters<typeof MockPayloadGenerator.generate>[1]) => {
  const { relayEnv } = testRender(
    <Routes>
      <Route path="/dashboard/defense/hunts/:huntId/runs/:runId" element={<RootHuntRun />} />
    </Routes>,
    {
      route: '/dashboard/defense/hunts/hunt-1/runs/run-1',
      userContext: createMockUserContext({ me: { name: 'admin', user_email: 'admin@opencti.io', capabilities: [{ name: BYPASS }] } as never }),
    },
  );
  await act(async () => {
    relayEnv.mock.resolveMostRecentOperation((operation) => MockPayloadGenerator.generate(operation, resolvers));
  });
};

const hunt = () => ({ id: 'hunt-1', name: 'Encoded PowerShell', currentUserAccessRight: 'admin' });
const run = (overrides: Record<string, unknown> = {}) => ({
  id: 'run-1',
  hunt_id: 'hunt-1',
  hunt_run_status: 'completed',
  created_at: '2026-10-05T12:00:00.000Z',
  ...overrides,
});

describe('Hunt run route', () => {
  it('reads the run of the hunt in the URL, under the breadcrumbs of its hunt', async () => {
    await renderRunPage({ Hunt: hunt, HuntRun: () => run() });
    const page = screen.getByTestId('hunt-run-page');
    const breadcrumbs = within(page).getByTestId('navigation');
    expect(breadcrumbs).toHaveTextContent('Defense');
    expect(within(breadcrumbs).getByRole('link', { name: 'Hunts' })).toHaveAttribute('href', '/dashboard/defense/hunts');
    expect(within(breadcrumbs).getByRole('link', { name: 'Encoded PowerShell' })).toHaveAttribute('href', '/dashboard/defense/hunts/hunt-1');
    expect(breadcrumbs).toHaveTextContent(/Run of .*2026/);
    const body = within(page).getByTestId('hunt-run-body');
    expect(body).toHaveTextContent(/^Run of .*2026/);
    // The edit right of the hunt, the user being able to change it
    expect(body).toHaveAttribute('data-can-edit', 'true');
  });

  it('never shows the run of another hunt under this one', async () => {
    await renderRunPage({ Hunt: hunt, HuntRun: () => run({ hunt_id: 'hunt-2' }) });
    expect(screen.queryByTestId('hunt-run-body')).not.toBeInTheDocument();
    expect(screen.getByTestId('hunt-run-not-found')).toHaveTextContent('This run cannot be found');
    expect(screen.getByTestId('hunt-run-back')).toHaveAttribute('href', '/dashboard/defense/hunts/hunt-1/runs');
    expect(within(screen.getByTestId('navigation')).getByText('Encoded PowerShell')).toBeInTheDocument();
  });

  it('says the page is not found when the hunt cannot be read', async () => {
    await renderRunPage({ Query: () => ({ hunt: null, huntRun: null }) });
    expect(screen.queryByTestId('hunt-run-body')).not.toBeInTheDocument();
    expect(screen.getByText('This page is not found on this OpenCTI application.')).toBeInTheDocument();
  });
});
