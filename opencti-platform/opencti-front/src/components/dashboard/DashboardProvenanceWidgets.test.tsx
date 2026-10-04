import React, { ReactNode } from 'react';
import { describe, expect, it, vi } from 'vitest';
import { screen } from '@testing-library/react';
import testRender from '../../utils/tests/test-render';
import useHelper from '../../utils/hooks/useHelper';
import DashboardEntitiesViz from './DashboardEntitiesViz';
import DashboardRelationshipsViz from './DashboardRelationshipsViz';
import type { Widget } from '../../utils/widget/widget';

vi.mock('../../utils/hooks/useHelper', () => ({
  default: vi.fn(),
}));

// The real widgets run their aggregation query as soon as they are mounted
vi.mock('@components/common/provenance/ProvenanceFreshnessWidget', () => ({
  default: () => <div data-testid="provenance-freshness-widget" />,
}));
vi.mock('@components/common/provenance/ProvenanceSingleSourcedWidget', () => ({
  default: () => <div data-testid="provenance-single-sourced-widget" />,
}));

const setProvenanceEnabled = (enabled: boolean) => {
  vi.mocked(useHelper).mockReturnValue({ isProvenanceEnabled: () => enabled } as unknown as ReturnType<typeof useHelper>);
};

const widgetOf = (type: string, title?: string) => ({
  id: 'provenance-widget',
  type,
  perspective: 'entities',
  dataSelection: [],
  parameters: title ? { title } : {},
} as unknown as Widget);

const perspectives: [string, (widget: Widget) => ReactNode][] = [
  ['entities', (widget) => <DashboardEntitiesViz widget={widget} config={{}} />],
  ['relationships', (widget) => <DashboardRelationshipsViz widget={widget} config={{}} />],
];

describe.each(perspectives)('Saved provenance widgets of the %s perspective', (_perspective, render) => {
  it('should say that provenance is disabled instead of mounting the widget', () => {
    setProvenanceEnabled(false);
    testRender(render(widgetOf('provenance-freshness')));
    expect(screen.getByText('Provenance is disabled on this platform.')).toBeInTheDocument();
    expect(screen.getByText('Knowledge freshness - days since the last assertion')).toBeInTheDocument();
    expect(screen.queryByTestId('provenance-freshness-widget')).not.toBeInTheDocument();
  });

  it('should give the next step and the documentation of the configuration', () => {
    setProvenanceEnabled(false);
    testRender(render(widgetOf('provenance-freshness')));
    expect(screen.getByText('An administrator enables it in the platform configuration (provenance:enabled).')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Learn more' })).toHaveAttribute('href', 'https://docs.opencti.io/latest/usage/provenance/#configuration');
  });

  it('should keep the title given to the widget while provenance is disabled', () => {
    setProvenanceEnabled(false);
    testRender(render(widgetOf('provenance-single-sourced', 'Single-sourced intrusion sets')));
    expect(screen.getByText('Single-sourced intrusion sets')).toBeInTheDocument();
    expect(screen.queryByTestId('provenance-single-sourced-widget')).not.toBeInTheDocument();
  });

  it('should mount the widget while provenance is enabled', () => {
    setProvenanceEnabled(true);
    testRender(render(widgetOf('provenance-single-sourced')));
    expect(screen.getByTestId('provenance-single-sourced-widget')).toBeInTheDocument();
    expect(screen.queryByText('Provenance is disabled on this platform.')).not.toBeInTheDocument();
  });
});
