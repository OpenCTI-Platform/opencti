import React, { ComponentProps } from 'react';
import { describe, expect, it, vi } from 'vitest';
import { screen } from '@testing-library/react';
import testRender from '../../../../utils/tests/test-render';

vi.mock('../../../../relay/environment', () => ({
  APP_BASE_PATH: '',
  MESSAGING$: { messages$: { subscribe: () => ({}) } },
  environment: {},
  fetchQuery: vi.fn(),
}));

vi.mock('../../../../components/dashboard/WidgetNoData', () => ({
  default: () => <div data-testid="widget-no-data" />,
}));

import { buildHuntRunsWidgetVariables, HuntRunsWidgetRows } from './HuntRunsWidgetList';

const config = { relativeDate: null, startDate: null, endDate: null };
const runFilter = { mode: 'and', filters: [{ key: 'entity_type', values: ['Hunt-Run'], operator: 'eq', mode: 'or' }], filterGroups: [] };

describe('buildHuntRunsWidgetVariables', () => {
  it('should list the newest runs first and leave the translation previews out', () => {
    const variables = buildHuntRunsWidgetVariables([{ filters: runFilter, number: 5 }], config);
    expect(variables).toMatchObject({ first: 5, orderBy: 'created_at', orderMode: 'desc' });
    expect(variables.filters?.filters).toContainEqual(expect.objectContaining({ key: ['hunt_run_mode'], values: ['preview'], operator: 'not_eq' }));
    expect(variables.filters?.filterGroups?.[0]?.filters).toContainEqual(expect.objectContaining({ key: ['entity_type'], values: ['Hunt-Run'] }));
  });

  it('should keep a sort the runs support and fall back to the creation date otherwise', () => {
    expect(buildHuntRunsWidgetVariables([{ filters: runFilter, sort_by: 'hits_count', sort_mode: 'asc' }], config)).toMatchObject({ orderBy: 'hits_count', orderMode: 'asc' });
    expect(buildHuntRunsWidgetVariables([{ filters: runFilter, sort_by: 'name' }], config)).toMatchObject({ orderBy: 'created_at' });
  });
});

describe('HuntRunsWidgetRows', () => {
  const run: ComponentProps<typeof HuntRunsWidgetRows>['runs'][number] = {
    id: 'run-1',
    hunt_id: 'hunt-1',
    hunt_run_status: 'completed',
    hits_count: 2,
    verdict: 'true_positive',
    created_at: '2026-10-15T10:00:00.000Z',
    connector_name: 'Splunk connector',
    hunt: { id: 'hunt-1', name: 'Cobalt Strike beacons' },
    securityPlatform: { id: 'platform-1', name: 'Splunk prod' },
  };

  it('should link each run to its page with its hunt, platform and hits', () => {
    testRender(<HuntRunsWidgetRows runs={[run]} />);
    expect(screen.getByText('Cobalt Strike beacons')).toBeTruthy();
    expect(screen.getByText('Splunk prod')).toBeTruthy();
    expect(screen.getByRole('link').getAttribute('href')).toContain('/hunts/hunt-1/runs/run-1');
  });

  it('should name a deleted hunt and show the empty state without runs', () => {
    testRender(<HuntRunsWidgetRows runs={[{ ...run, hunt: null, securityPlatform: null }]} />);
    expect(screen.getByText('Deleted hunt')).toBeTruthy();
    expect(screen.getByText('Splunk connector')).toBeTruthy();
    testRender(<HuntRunsWidgetRows runs={[]} />);
    expect(screen.getByTestId('widget-no-data')).toBeTruthy();
  });
});
