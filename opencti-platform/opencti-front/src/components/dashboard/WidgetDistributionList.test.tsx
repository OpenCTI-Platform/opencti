import { describe, expect, it, vi } from 'vitest';
import { screen } from '@testing-library/react';
import WidgetDistributionList from './WidgetDistributionList';
import testRender from '../../utils/tests/test-render';

vi.mock('../../utils/hooks/useAppData', () => ({
  useComputeLink: () => (node: { id: string }) => `/dashboard/entity/${node.id}`,
}));

const data = [
  { label: 'Malware', value: 12, id: 'a', type: 'Malware' },
  { label: 'Tool', value: 7, id: 'b', type: 'Tool' },
];

describe('WidgetDistributionList', () => {
  it('renders counts as plain text without a drilldown resolver', () => {
    testRender(<WidgetDistributionList data={data} />);
    expect(screen.getByText('12').closest('a')).toBeNull();
  });

  it('links each count to its own resolved list', () => {
    const getDrilldownLink = vi.fn((index: number) => `/dashboard/data/entities?filters=${index}`);
    testRender(<WidgetDistributionList data={data} getDrilldownLink={getDrilldownLink} />);
    expect(screen.getByText('12').closest('a')?.getAttribute('href')).toContain('filters=0');
    expect(screen.getByText('7').closest('a')?.getAttribute('href')).toContain('filters=1');
  });

  it('leaves a count inert when its link resolves to null', () => {
    testRender(<WidgetDistributionList data={data} getDrilldownLink={() => null} />);
    expect(screen.getByText('12').closest('a')).toBeNull();
  });

  it('keeps the label link pointing at the entity', () => {
    testRender(<WidgetDistributionList data={data} getDrilldownLink={() => '/dashboard/data/entities'} />);
    expect(screen.getByText('Malware').closest('a')?.getAttribute('href')).toContain('/dashboard/entity/a');
  });

  /**
   * The row itself is already an anchor to the entity. Nesting the count anchor
   * inside it would be invalid HTML, would expose a single confused control to
   * assistive technology, and would make the destination depend on which
   * handler happens to call preventDefault first.
   */
  it('renders the count link outside the row link, never nested in it', () => {
    testRender(<WidgetDistributionList data={data} getDrilldownLink={() => '/dashboard/data/entities'} />);
    const countLink = screen.getByText('12').closest('a');
    expect(countLink?.getAttribute('href')).toContain('/dashboard/data/entities');
    expect(countLink?.parentElement?.closest('a')).toBeNull();
  });
});
