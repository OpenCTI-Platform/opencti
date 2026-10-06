import { describe, expect, it } from 'vitest';
import { fromB64 } from '../../../utils/String';
import { buildDashboardTemplateExport, buildDashboardTemplateFile, DASHBOARD_TEMPLATES } from './dashboardTemplates';
import { defenseCoverageDashboardTemplate } from './defenseCoverageDashboardTemplate';

const translate = (text: string) => `[${text}]`;

const decodeManifest = (manifest: string) => JSON.parse(fromB64(manifest));

describe('dashboard templates', () => {
  it('registers the defense coverage template', () => {
    expect(DASHBOARD_TEMPLATES.map((template) => template.id)).toContain('defense-coverage');
  });

  it('builds an importable dashboard export', () => {
    const exported = buildDashboardTemplateExport(defenseCoverageDashboardTemplate, translate);
    expect(exported.type).toBe('dashboard');
    expect(exported.configuration.name).toBe('[Defense coverage]');
    const manifest = decodeManifest(exported.configuration.manifest);
    expect(manifest.config).toEqual({});
    expect(Object.keys(manifest.widgets)).toHaveLength(defenseCoverageDashboardTemplate.widgets.length);
  });

  it('translates titles and fills the selection defaults', () => {
    const manifest = decodeManifest(buildDashboardTemplateExport(defenseCoverageDashboardTemplate, translate).configuration.manifest);
    const byPatternType = manifest.widgets['0a09d3f0-0001-4d09-9a09-000000000006'];
    expect(byPatternType.parameters.title).toBe('[Detection rules by pattern type]');
    expect(byPatternType.dataSelection[0]).toMatchObject({ label: '', attribute: 'pattern_type', date_attribute: 'created_at', isTo: true, number: 12 });
    expect(byPatternType.layout).toMatchObject({ i: byPatternType.id, w: 6, h: 7 });
  });

  it('keeps the widgets inside the 12 column grid without overlap', () => {
    DASHBOARD_TEMPLATES.forEach((template) => {
      const cells = new Set<string>();
      template.widgets.forEach(({ layout }) => {
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

  it('wraps the export in a JSON file', async () => {
    const file = buildDashboardTemplateFile(defenseCoverageDashboardTemplate, translate);
    expect(file.name).toBe('defense-coverage.json');
    expect(JSON.parse(await file.text()).type).toBe('dashboard');
  });
});
