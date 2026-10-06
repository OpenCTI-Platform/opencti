import React from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { act, screen, waitFor } from '@testing-library/react';
import testRender from '../../../../utils/tests/test-render';
import { DashboardRefreshProvider, useDashboardRefreshPendingState } from '../../../../components/dashboard/DashboardRefreshContext';
import KnowledgeHealthWidget from './KnowledgeHealthWidget';

const { read } = vi.hoisted(() => ({ read: vi.fn() }));

vi.mock('../../../../relay/environment', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../../../relay/environment')>();
  return { ...actual, fetchQuery: () => ({ toPromise: () => read() }) };
});

const withoutSnapshot = {
  knowledgeHealth: null,
  knowledgeHealthSnapshots: { edges: [] },
  curationStatistics: { open_count: 0, open_by_kind: [] },
};

const NO_SNAPSHOT = 'No Knowledge health snapshot yet: the curation manager computes one once a day.';

describe('KnowledgeHealthWidget', () => {
  beforeEach(() => {
    read.mockReset();
    read.mockResolvedValue(withoutSnapshot);
  });

  it('reads the Knowledge health again at each dashboard refresh', async () => {
    const widget = (refreshToken: number) => (
      <DashboardRefreshProvider refreshToken={refreshToken}>
        <KnowledgeHealthWidget variant="knowledge-health-score" />
      </DashboardRefreshProvider>
    );
    const { rerender } = testRender(widget(1));
    expect(await screen.findByText(NO_SNAPSHOT)).toBeInTheDocument();
    expect(read).toHaveBeenCalledTimes(1);

    rerender(widget(2));
    await waitFor(() => expect(read).toHaveBeenCalledTimes(2));
    // The current figures stay on screen while the refresh is read.
    expect(screen.getByText(NO_SNAPSHOT)).toBeInTheDocument();
  });

  it('keeps the dashboard refreshing until the latest read answers', async () => {
    const answers: Array<(value: unknown) => void> = [];
    read.mockImplementation(() => new Promise((resolve) => {
      answers.push(resolve);
    }));
    const Pending = () => <span data-testid="dashboard-pending">{String(useDashboardRefreshPendingState())}</span>;
    const widget = (refreshToken: number) => (
      <DashboardRefreshProvider refreshToken={refreshToken}>
        <Pending />
        <KnowledgeHealthWidget variant="knowledge-health-score" />
      </DashboardRefreshProvider>
    );
    const { rerender } = testRender(widget(1));
    await waitFor(() => expect(answers).toHaveLength(1));
    rerender(widget(2));
    await waitFor(() => expect(answers).toHaveLength(2));
    expect(screen.getByTestId('dashboard-pending')).toHaveTextContent('true');
    const answer = async (index: number) => act(async () => {
      answers[index](withoutSnapshot);
      await new Promise((resolve) => {
        setTimeout(resolve, 0);
      });
    });
    // The read the refresh replaced answers first: the dashboard still waits for the latest one.
    await answer(0);
    expect(screen.getByTestId('dashboard-pending')).toHaveTextContent('true');
    await answer(1);
    expect(screen.getByTestId('dashboard-pending')).toHaveTextContent('false');
  });

  it('shows no data when the Knowledge health cannot be read', async () => {
    read.mockRejectedValue(new Error('forbidden'));
    testRender(<KnowledgeHealthWidget variant="curation-open-proposals" />);
    expect(await screen.findByText('Knowledge health is not available here: it needs the capability to access knowledge.')).toBeInTheDocument();
  });
});
