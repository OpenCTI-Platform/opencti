import { describe, expect, it } from 'vitest';
import { fromB64 } from '../../../utils/String';
import { getCurrentCategory } from '../../../utils/widget/widgetUtils';
import { buildDashboardTemplateExport, buildDashboardTemplateFile, DASHBOARD_TEMPLATES } from './dashboardTemplates';
import { knowledgeHealthDashboardTemplate } from './knowledgeHealthDashboardTemplate';

const translate = (text: string) => `[${text}]`;

const decodeManifest = (manifest: string) => JSON.parse(fromB64(manifest));

describe('Knowledge health dashboard template', () => {
  it('is registered as a built-in template', () => {
    expect(DASHBOARD_TEMPLATES.map((template) => template.id)).toContain('knowledge-health');
  });

  it('only uses the curation widgets of the catalog, which need no data selection', () => {
    knowledgeHealthDashboardTemplate.widgets.forEach((widget) => {
      expect(getCurrentCategory(widget.type)).toBe('curation');
      expect(widget.perspective).toBeNull();
      expect(widget.dataSelection).toEqual([]);
    });
  });

  it('builds an importable dashboard export with translated titles', () => {
    const exported = buildDashboardTemplateExport(knowledgeHealthDashboardTemplate, translate);
    expect(exported.type).toBe('dashboard');
    expect(exported.configuration.name).toBe('[Knowledge health]');
    const manifest = decodeManifest(exported.configuration.manifest);
    expect(Object.keys(manifest.widgets)).toHaveLength(3);
    const score = manifest.widgets['0a05c0de-0001-4c05-9a05-000000000001'];
    expect(score).toMatchObject({ type: 'knowledge-health-score', perspective: null, dataSelection: [] });
    expect(score.parameters.title).toBe('[Knowledge health score]');
    expect(score.layout).toMatchObject({ i: score.id, x: 0, y: 0, w: 4, h: 4 });
  });

  it('keeps the widgets inside the 12 column grid without overlap', () => {
    const cells = new Set<string>();
    knowledgeHealthDashboardTemplate.widgets.forEach(({ layout }) => {
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

  it('wraps the export in a JSON file named after the template', async () => {
    const file = buildDashboardTemplateFile(knowledgeHealthDashboardTemplate, translate);
    expect(file.name).toBe('knowledge-health.json');
    expect(JSON.parse(await file.text()).configuration.name).toBe('[Knowledge health]');
  });
});
