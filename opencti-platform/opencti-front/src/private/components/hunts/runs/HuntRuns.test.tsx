import React from 'react';
import { describe, expect, it, vi } from 'vitest';
import { screen } from '@testing-library/react';
import { Route, Routes, useNavigate, useParams } from 'react-router';
import testRender from '../../../../utils/tests/test-render';
import RootHunts from '../RootHunts';
import HuntRuns from './HuntRuns';

// The page of a hunt holds its Runs tab
vi.mock('../Root', () => {
  const RootHunt = () => <HuntRuns hunt={{ id: 'hunt-1', hunt_status: 'active', hunt_type: 'telemetry', time_window_hours: 24 }} canEdit />;
  return { default: RootHunt };
});

vi.mock('./RootHuntRun', () => {
  const RootHuntRun = () => {
    const { huntId, runId } = useParams();
    return <div data-testid="hunt-run-page">{`${huntId} ${runId}`}</div>;
  };
  return { default: RootHuntRun };
});

// A row of the table links to its run and navigates there on click
vi.mock('../../../../components/dataGrid/DataTable', () => {
  const DataTable = ({ getComputeLink }: { getComputeLink: (run: { id: string }) => string }) => {
    const navigate = useNavigate();
    const link = getComputeLink({ id: 'run-1' });
    return (
      <a
        href={link}
        data-testid="hunt-run-row"
        onClick={(event) => {
          event.preventDefault();
          navigate(link);
        }}
      >
        run-1
      </a>
    );
  };
  return { default: DataTable };
});

const renderHunts = (route: string) => testRender(
  <Routes>
    <Route path="/dashboard/defense/hunts/*" element={<RootHunts />} />
  </Routes>,
  { route },
);

describe('Runs of a hunt', () => {
  it('opens a run on its own page, in place of the list of the runs', async () => {
    const { user } = renderHunts('/dashboard/defense/hunts/hunt-1/runs');
    const row = await screen.findByTestId('hunt-run-row');
    expect(row).toHaveAttribute('href', '/dashboard/defense/hunts/hunt-1/runs/run-1');
    await user.click(row);
    expect(await screen.findByTestId('hunt-run-page')).toHaveTextContent('hunt-1 run-1');
    expect(screen.queryByTestId('hunt-runs-page')).not.toBeInTheDocument();
    expect(window.location.pathname).toBe('/dashboard/defense/hunts/hunt-1/runs/run-1');
  });

  it('opens the page of a run from a link to it', async () => {
    renderHunts('/dashboard/defense/hunts/hunt-1/runs/run-1');
    expect(await screen.findByTestId('hunt-run-page')).toHaveTextContent('hunt-1 run-1');
    expect(screen.queryByTestId('hunt-runs-page')).not.toBeInTheDocument();
  });
});
