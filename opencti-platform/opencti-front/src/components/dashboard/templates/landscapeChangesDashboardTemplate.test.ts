import { describe, expect, it } from 'vitest';
import { fromB64 } from '../../../utils/String';
import { buildDashboardTemplateExport, DASHBOARD_TEMPLATES } from './dashboardTemplates';
import { landscapeChangesDashboardTemplate } from './landscapeChangesDashboardTemplate';

const translate = (text: string) => `[${text}]`;
const LANDSCAPE_WIDGET_TYPES = ['landscape-relationships', 'landscape-techniques', 'landscape-top-entities'];

describe('Threat landscape changes dashboard template', () => {
  it('is offered in the dashboard templates', () => {
    expect(DASHBOARD_TEMPLATES.map((template) => template.id)).toContain('landscape-changes');
  });

  it('builds an importable dashboard export with translated titles', () => {
    const exported = buildDashboardTemplateExport(landscapeChangesDashboardTemplate, translate);
    expect(exported.type).toBe('dashboard');
    expect(exported.configuration.name).toBe('[Threat landscape changes]');
    const manifest = JSON.parse(fromB64(exported.configuration.manifest));
    expect(Object.keys(manifest.widgets)).toHaveLength(landscapeChangesDashboardTemplate.widgets.length);
    const topThreats = manifest.widgets['08a1d5c0-0008-4e08-a008-000000000001'];
    expect(topThreats.parameters.title).toBe('[Top changed threats]');
    expect(topThreats.layout).toMatchObject({ i: topThreats.id, w: 6, h: 4 });
  });

  it('only uses landscape widgets scoped by entity type on the entities perspective', () => {
    landscapeChangesDashboardTemplate.widgets.forEach((widget) => {
      expect(LANDSCAPE_WIDGET_TYPES).toContain(widget.type);
      expect(widget.perspective).toBe('entities');
      expect(widget.dataSelection).toHaveLength(1);
      expect(widget.dataSelection[0].filters.filters[0]).toMatchObject({ key: ['entity_type'], operator: 'eq' });
    });
  });

  it('keeps the widgets inside the 12 column grid without overlap', () => {
    const cells = new Set<string>();
    landscapeChangesDashboardTemplate.widgets.forEach(({ layout }) => {
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
