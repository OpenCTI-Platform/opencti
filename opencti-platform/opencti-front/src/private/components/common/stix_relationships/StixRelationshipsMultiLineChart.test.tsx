import React from 'react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import testRender from '../../../../utils/tests/test-render';

type BuildQueryVariables = (
  dataSelection: unknown[],
  config: unknown,
  parameters?: { interval?: string },
) => Record<string, unknown>;

let capturedBuildQueryVariables: BuildQueryVariables | null = null;
let capturedParameters: { interval?: string } | undefined;

beforeEach(() => {
  capturedBuildQueryVariables = null;
  capturedParameters = undefined;
});

vi.mock('apexcharts', () => ({ default: class ApexChartsMock {} }));

vi.mock('../../../../components/dashboard/useDashboardViz', () => ({
  default: ({ dataSelection, buildQueryVariables, parameters }: {
    dataSelection: unknown[];
    buildQueryVariables: BuildQueryVariables;
    parameters?: { interval?: string };
  }) => {
    capturedBuildQueryVariables = buildQueryVariables;
    capturedParameters = parameters;
    return {
      resolvedDataSelection: dataSelection,
      isMissingHostEntity: false,
      isPreviewMode: false,
      queryRef: null,
    };
  },
}));

vi.mock('../../../../components/dashboard/WidgetContainer', () => ({
  default: ({ children }: { children: React.ReactNode }) => <div data-testid="widget-container">{children}</div>,
}));

vi.mock('../../../../components/dashboard/WidgetNoData', () => ({
  default: () => <div data-testid="widget-no-data" />,
}));

vi.mock('../../../../components/dashboard/WidgetMultiLines', () => ({
  default: () => <div data-testid="widget-multi-lines" />,
}));

vi.mock('../../../../components/dashboard/WidgetNoHostEntity', () => ({
  default: () => <div data-testid="widget-no-host" />,
}));

vi.mock('../../../../components/Loader', () => ({
  default: () => <div data-testid="loader" />,
  LoaderVariant: { inElement: 'inElement' },
}));

import StixRelationshipsMultiLineChart from './StixRelationshipsMultiLineChart';

describe('StixRelationshipsMultiLineChart', () => {
  const baseProps = {
    config: { relativeDate: null, startDate: null, endDate: null },
    dataSelection: [{
      filters: { mode: 'and' as const, filters: [], filterGroups: [] },
      date_attribute: 'created_at',
    }],
  };

  it('forwards parameters.interval into the time-series query variables', () => {
    testRender(<StixRelationshipsMultiLineChart {...baseProps} parameters={{ interval: 'week' }} />);
    expect(typeof capturedBuildQueryVariables).toBe('function');
    const variables = capturedBuildQueryVariables!(baseProps.dataSelection, baseProps.config, capturedParameters);
    expect(variables.interval).toBe('week');
  });

  it('defaults interval to day when parameters.interval is not provided', () => {
    testRender(<StixRelationshipsMultiLineChart {...baseProps} parameters={{}} />);
    expect(typeof capturedBuildQueryVariables).toBe('function');
    const variables = capturedBuildQueryVariables!(baseProps.dataSelection, baseProps.config, capturedParameters);
    expect(variables.interval).toBe('day');
  });
});
