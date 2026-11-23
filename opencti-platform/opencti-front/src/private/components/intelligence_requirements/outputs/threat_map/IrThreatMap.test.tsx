import React from 'react';
import { describe, expect, it, vi } from 'vitest';
import { act, screen } from '@testing-library/react';
import testRender from '../../../../../utils/tests/test-render';
import IrThreatMap from './IrThreatMap';
import IrThreatMapTooltip from './IrThreatMapTooltip';
import { IrThreatMapMarker, IrThreatMapMatch } from './irThreatMapUtils';

// The chart itself (ApexCharts) does not render in jsdom: the mock keeps the series and the callbacks the map gives it.
type ScatterProps = {
  series: { data: { meta: { group: IrThreatMapMarker[] } }[] }[];
  options: {
    dataPointSelection: (e: { offsetX: number; offsetY: number }, _: unknown, opts: unknown) => void;
    dataPointMouseEnter: (e: { offsetX: number; offsetY: number }, _: unknown, opts: unknown) => void;
    labelsFormatter: (value: unknown, opts: unknown) => unknown;
  };
};
const scatter: { last?: ScatterProps } = {};
vi.mock('../../../../../components/dashboard/WidgetScatter', () => ({
  default: (props: ScatterProps) => {
    scatter.last = props;
    return <div data-testid="scatter">{props.series.length}</div>;
  },
}));

const recent = (hoursAgo: number) => new Date(Date.now() - hoursAgo * 3600 * 1000).toISOString();

const match = (id: string, overwrites: Partial<IrThreatMapMatch> = {}): IrThreatMapMatch => ({
  id,
  match_status: 'auto',
  match_excluded: false,
  match_score: 60,
  match_entity_id: `entity-${id}`,
  match_entity_type: 'Vulnerability',
  match_entity_name: `CVE ${id}`,
  match_last_fact_at: recent(2),
  match_criteria_ids: ['c1'],
  entity: null,
  ...overwrites,
});

const pointOpts = (seriesIndex: number) => ({
  seriesIndex,
  dataPointIndex: 0,
  w: { config: { series: scatter.last?.series } },
});

describe('IrThreatMap', () => {
  it('draws the entities of the requirement and opens the drawer of a single entity on click', () => {
    const onOpen = vi.fn();
    testRender(<IrThreatMap matches={[match('a'), match('b', { match_entity_type: 'Software', match_score: 90 })]} onOpen={onOpen} />);
    expect(screen.getByText('Threat map')).toBeInTheDocument();
    expect(screen.getByTestId('scatter')).toHaveTextContent('2');
    expect(screen.getByRole('button', { name: /Vulnerability/ })).toHaveAttribute('aria-pressed', 'true');

    act(() => scatter.last?.options.dataPointSelection({ offsetX: 10, offsetY: 10 }, null, pointOpts(0)));
    expect(onOpen).toHaveBeenCalledTimes(1);
    expect(scatter.last?.options.labelsFormatter(null, pointOpts(0))).toEqual('');
  });

  it('lists a cluster on click and opens one of its entities from the list', async () => {
    const onOpen = vi.fn();
    const { user } = testRender(<IrThreatMap matches={[match('a', { match_score: 60 }), match('b', { match_score: 62 })]} onOpen={onOpen} />);
    expect(screen.getByTestId('scatter')).toHaveTextContent('1');
    expect(scatter.last?.options.labelsFormatter(null, pointOpts(0))).toEqual(2);

    act(() => scatter.last?.options.dataPointSelection({ offsetX: 10, offsetY: 10 }, null, pointOpts(0)));
    expect(onOpen).not.toHaveBeenCalled();
    await user.click(screen.getByRole('button', { name: 'CVE a' }));
    expect(onOpen).toHaveBeenCalledWith('a');
    expect(screen.queryByRole('dialog', { name: 'Threat map' })).not.toBeInTheDocument();
  });

  it('shows the entities of a marker on hover', () => {
    testRender(<IrThreatMap matches={[match('a')]} onOpen={vi.fn()} />);
    act(() => scatter.last?.options.dataPointMouseEnter({ offsetX: 10, offsetY: 10 }, null, pointOpts(0)));
    expect(screen.getByRole('dialog', { name: 'Threat map' })).toBeInTheDocument();
  });

  it('says so when no entity of the requirement falls in the window', () => {
    testRender(<IrThreatMap matches={[match('old', { match_last_fact_at: '2020-01-01T00:00:00.000Z' })]} onOpen={vi.fn()} />);
    expect(screen.getByText('No entity matches the selected filters in this time window')).toBeInTheDocument();
  });
});

describe('IrThreatMapTooltip', () => {
  const marker = (id: string): IrThreatMapMarker => ({ id, entityId: `e-${id}`, date: recent(1), score: 50, name: `Entity ${id}`, type: 'Malware', matchedCriteria: 2 });

  it('renders nothing without data', () => {
    const { container } = testRender(<IrThreatMapTooltip onOpen={vi.fn()} x={0} y={0} />);
    expect(container).toBeEmptyDOMElement();
  });

  it('caps the list and opens a row from the keyboard', async () => {
    const onOpen = vi.fn();
    const data = Array.from({ length: 10 }, (_, i) => marker(String(i)));
    const { user } = testRender(<IrThreatMapTooltip data={data} onOpen={onOpen} x={0} y={0} />);
    expect(screen.getAllByRole('button')).toHaveLength(8);
    expect(screen.getByText('2 more entities')).toBeInTheDocument();
    screen.getByRole('button', { name: 'Entity 3' }).focus();
    await user.keyboard('{Enter}');
    expect(onOpen).toHaveBeenCalledWith('3');
  });
});
