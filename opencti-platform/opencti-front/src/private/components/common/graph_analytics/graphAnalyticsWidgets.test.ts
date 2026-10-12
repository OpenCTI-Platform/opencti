import { describe, expect, it } from 'vitest';
import { buildGraphClustersSizeVariables } from './GraphClustersSizeWidget';
import { buildGraphSimilarityMatrixVariables } from './GraphSimilarityMatrixWidget';
import { buildGraphTopHubsVariables } from './GraphTopHubsWidget';
import type { WidgetDataSelection } from '../../../../utils/widget/widget';

const selection = (number?: number): WidgetDataSelection => ({
  number,
  perspective: 'entities',
  date_attribute: 'created_at',
  filters: {
    mode: 'and',
    filters: [{ key: 'entity_type', values: ['Intrusion-Set'], operator: 'eq', mode: 'or' }],
    filterGroups: [],
  },
});

describe('graph analytics widgets query variables', () => {
  it('bounds the number of entities of a similarity matrix', () => {
    expect(buildGraphSimilarityMatrixVariables([selection()], {}).first).toBe(10);
    expect(buildGraphSimilarityMatrixVariables([selection(40)], {}).first).toBe(25);
    expect(buildGraphSimilarityMatrixVariables([selection(1)], {}).first).toBe(2);
  });

  it('keeps the data selection filters of a similarity matrix', () => {
    const { filters } = buildGraphSimilarityMatrixVariables([selection(5)], {});
    expect(JSON.stringify(filters)).toContain('Intrusion-Set');
  });

  it('bounds the number of clusters and never filters members on the dashboard period', () => {
    const config = { startDate: '2026-01-01T00:00:00.000Z', endDate: '2026-06-01T00:00:00.000Z' };
    const variables = buildGraphClustersSizeVariables([selection(50)], config, { interval: 'week' });
    expect(variables.limit).toBe(20);
    expect(variables.interval).toBe('week');
    expect(variables.startDate).toBe(config.startDate);
    expect(variables.endDate).toBe(config.endDate);
    expect(JSON.stringify(variables.filters)).toContain('Intrusion-Set');
    expect(JSON.stringify(variables.filters)).not.toContain('2026-01-01');
    expect(buildGraphClustersSizeVariables([selection()], {}).limit).toBe(5);
  });

  it('bounds the number of top hubs and filters them on the dashboard period', () => {
    const config = { startDate: '2026-01-01T00:00:00.000Z', endDate: '2026-06-01T00:00:00.000Z' };
    const variables = buildGraphTopHubsVariables([selection(80)], config);
    expect(variables.first).toBe(50);
    expect(variables.types).toEqual(['Stix-Core-Object']);
    expect(JSON.stringify(variables.filters)).toContain('Intrusion-Set');
    expect(JSON.stringify(variables.filters)).toContain('2026-01-01');
    expect(buildGraphTopHubsVariables([selection()], {}).first).toBe(10);
    expect(buildGraphTopHubsVariables([selection(0)], {}).first).toBe(10);
  });
});
