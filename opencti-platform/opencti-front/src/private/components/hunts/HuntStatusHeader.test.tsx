import React from 'react';
import { describe, expect, it } from 'vitest';
import { screen, within } from '@testing-library/react';
import testRender from '../../../utils/tests/test-render';
import { HuntReadinessChecklist, huntPrimaryStatusAction } from './HuntStatusHeader';
import { huntLogicMissingSentence } from './HuntLogic';
import { HUNT_STATUS_MEANINGS, HUNT_STATUSES } from './hunt-utils';

const item = (key: string, status: string, template: string, values: Record<string, string> = {}) => ({
  key,
  status,
  template,
  values: Object.entries(values).map(([name, value]) => ({ name, value })),
  message: template,
}) as never;

describe('Hunt status header', () => {
  it('gives each status its primary action', () => {
    expect(huntPrimaryStatusAction('draft')).toEqual({ to: 'active', label: 'Activate' });
    expect(huntPrimaryStatusAction('active')).toEqual({ to: 'paused', label: 'Pause' });
    expect(huntPrimaryStatusAction('paused')).toEqual({ to: 'active', label: 'Resume' });
    expect(huntPrimaryStatusAction('retired')).toEqual({ to: 'draft', label: 'Reopen as draft' });
    expect(huntPrimaryStatusAction('unknown')).toBeNull();
  });

  it('explains every status in one line', () => {
    HUNT_STATUSES.forEach((status) => expect(HUNT_STATUS_MEANINGS[status].length).toBeGreaterThan(10));
    expect(HUNT_STATUS_MEANINGS.draft).toBe('The hunt is being written; it never runs.');
  });

  it('lists each readiness item with the place to fix the unmet ones', () => {
    testRender(
      <HuntReadinessChecklist
        huntId="hunt-id"
        items={[
          item('logic', 'unmet', 'Add a Sigma rule or a native query'),
          item('connector', 'unmet', 'No hunt connector can run it on the platforms of its scope: deploy a hunt connector or widen the scope'),
          item('schedule', 'met', 'Manual: it runs when you click Run now'),
          item('scope', 'met', 'Runs on {platforms}', { platforms: 'Splunk Production' }),
        ]}
      />,
    );
    const logic = screen.getByTestId('hunt-readiness-logic');
    expect(logic).toHaveAttribute('data-status', 'unmet');
    expect(within(logic).getByText('Add a Sigma rule or a native query')).toBeInTheDocument();
    expect(within(logic).getByTestId('hunt-readiness-open-logic')).toHaveAttribute('href', '/dashboard/defense/hunts/hunt-id/logic');
    expect(within(screen.getByTestId('hunt-readiness-connector')).getByTestId('hunt-readiness-open-connectors')).toBeInTheDocument();
    // The values the platform sends fill the sentence; a met item offers no action
    const scope = screen.getByTestId('hunt-readiness-scope');
    expect(within(scope).getByText('Runs on Splunk Production')).toBeInTheDocument();
    expect(within(scope).queryByRole('button')).toBeNull();
  });

  it('words a missing logic as the platform does', () => {
    expect(huntLogicMissingSentence('telemetry', '', [])).toBe('Add a Sigma rule or a native query');
    expect(huntLogicMissingSentence('telemetry', '', [{ platform: 'internet' }])).toBe('Add a Sigma rule or a native query');
    expect(huntLogicMissingSentence('telemetry', 'title: x', [])).toBeNull();
    expect(huntLogicMissingSentence('telemetry', '', [{ platform: 'splunk' }])).toBeNull();
    expect(huntLogicMissingSentence('infrastructure', '', [{ platform: 'splunk' }])).toBe('Add a native query for the internet platform');
    expect(huntLogicMissingSentence('infrastructure', '', [{ platform: 'internet' }])).toBeNull();
  });
});
