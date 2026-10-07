import { describe, expect, it } from 'vitest';
import { fromB64 } from '../../../utils/String';
import { workspacesWidgetVisualizationTypes } from '../../../utils/widget/widgetUtils';
import { buildDashboardTemplateExport, DASHBOARD_TEMPLATES } from './dashboardTemplates';
import { graphAnalyticsDashboardTemplate } from './graphAnalyticsDashboardTemplate';

const translate = (text: string) => `[${text}]`;

const decodeManifest = (manifest: string) => JSON.parse(fromB64(manifest));

describe('graph analytics dashboard template', () => {
  it('is offered among the dashboard templates', () => {
    expect(DASHBOARD_TEMPLATES.map((template) => template.id)).toContain('graph-analytics');
  });

  it('builds an importable dashboard export with translated titles', () => {
    const exported = buildDashboardTemplateExport(graphAnalyticsDashboardTemplate, translate);
    expect(exported.type).toBe('dashboard');
    expect(exported.configuration.name).toBe('[Graph analytics]');
    const manifest = decodeManifest(exported.configuration.manifest);
    expect(Object.keys(manifest.widgets)).toHaveLength(5);
    const clusters = manifest.widgets['0a07d150-0001-4d1a-9a07-000000000001'];
    expect(clusters).toMatchObject({ type: 'graph-clusters-size', parameters: { title: '[Largest clusters - members over time]', interval: 'month' } });
    expect(clusters.layout).toMatchObject({ i: clusters.id, w: 6, h: 6 });
    const topHubs = manifest.widgets['0a07d150-0001-4d1a-9a07-000000000005'];
    expect(topHubs).toMatchObject({ type: 'graph-top-hubs', parameters: { title: '[Top hubs - by degree]' } });
  });

  it('only uses widgets of the dashboard catalog', () => {
    const catalog = workspacesWidgetVisualizationTypes.map((type) => type.key);
    graphAnalyticsDashboardTemplate.widgets.forEach((widget) => {
      expect(catalog).toContain(widget.type);
    });
  });

  it('ranks the hub lists by graph degree', () => {
    const lists = graphAnalyticsDashboardTemplate.widgets.filter((widget) => widget.type === 'list');
    expect(lists).toHaveLength(2);
    lists.forEach((widget) => {
      expect(widget.dataSelection[0]).toMatchObject({ sort_by: 'graph_degree', sort_mode: 'desc', number: 10 });
      expect(widget.dataSelection[0].columns?.map((column) => column.attribute)).toContain('graph_degree');
      expect(widget.dataSelection[0].filters.filters[0].key).toEqual(['entity_type']);
    });
  });

  it('keeps the widgets inside the 12 column grid without overlap', () => {
    const cells = new Set<string>();
    graphAnalyticsDashboardTemplate.widgets.forEach(({ layout }) => {
      expect(layout.x + layout.w).toBeLessThanOrEqual(12);
      for (let x = layout.x; x < layout.x + layout.w; x += 1) {
        for (let y = layout.y; y < layout.y + layout.h; y += 1) {
          const cell = `${x}:${y}`;
          expect(cells.has(cell)).toBe(false);
          cells.add(cell);
        }
      }
    });
  });
});
