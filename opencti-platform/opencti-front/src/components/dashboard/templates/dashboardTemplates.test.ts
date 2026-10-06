import { describe, expect, it } from 'vitest';
import { fromB64 } from '../../../utils/String';
import { buildDashboardTemplateExport, buildDashboardTemplateFile, DASHBOARD_TEMPLATES } from './dashboardTemplates';
import { disseminationAssuranceDashboardTemplate } from './disseminationAssuranceDashboardTemplate';

const translate = (text: string) => `[${text}]`;

const decodeManifest = (manifest: string) => JSON.parse(fromB64(manifest));

describe('dashboard templates', () => {
  it('registers the dissemination assurance template', () => {
    expect(DASHBOARD_TEMPLATES.map((template) => template.id)).toContain('dissemination-assurance');
  });

  it('builds an importable dashboard export', () => {
    const exported = buildDashboardTemplateExport(disseminationAssuranceDashboardTemplate, translate);
    expect(exported.type).toBe('dashboard');
    expect(exported.configuration.name).toBe('[Dissemination assurance]');
    const manifest = decodeManifest(exported.configuration.manifest);
    expect(manifest.config).toEqual({});
    expect(Object.keys(manifest.widgets)).toHaveLength(disseminationAssuranceDashboardTemplate.widgets.length);
  });

  it('translates titles and series labels and fills the selection defaults', () => {
    const manifest = decodeManifest(buildDashboardTemplateExport(disseminationAssuranceDashboardTemplate, translate).configuration.manifest);
    const byStatus = manifest.widgets['0a10d150-0001-4d1a-9a10-000000000007'];
    expect(byStatus.parameters.title).toBe('[Deployments by status]');
    expect(byStatus.dataSelection.map((selection: { label: string }) => selection.label)).toEqual(['[Live]', '[Pending]', '[Failed]', '[Removed]', '[Expired]']);
    const live = manifest.widgets['0a10d150-0001-4d1a-9a10-000000000001'];
    expect(live.dataSelection[0]).toMatchObject({ label: '', attribute: 'entity_type', date_attribute: 'created_at', isTo: true });
    expect(live.layout).toMatchObject({ i: live.id, w: 2, h: 2 });
  });

  it('places each validation outcome at the time it was observed', () => {
    const manifest = decodeManifest(buildDashboardTemplateExport(disseminationAssuranceDashboardTemplate, translate).configuration.manifest);
    const byOutcome = manifest.widgets['0a10d150-0001-4d1a-9a10-000000000008'];
    expect(byOutcome.dataSelection.map((selection: { date_attribute: string }) => selection.date_attribute))
      .toEqual(['last_validation_at', 'last_validation_at', 'last_validation_at', 'last_validation_at']);
  });

  it('scopes every relationship widget to deployed-on and every entity widget to indicators', () => {
    disseminationAssuranceDashboardTemplate.widgets.forEach((widget) => {
      widget.dataSelection.forEach((selection) => {
        const keys = selection.filters.filters.map((filter) => filter.key[0]);
        if (selection.perspective === 'relationships') {
          expect(selection.filters.filters[0]).toMatchObject({ key: ['relationship_type'], values: ['deployed-on'] });
        } else {
          expect(keys).toContain('entity_type');
        }
      });
    });
  });

  it('keeps the widgets inside the 12 column grid without overlap', () => {
    const cells = new Set<string>();
    disseminationAssuranceDashboardTemplate.widgets.forEach(({ layout }) => {
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

  it('wraps the export in a JSON file', async () => {
    const file = buildDashboardTemplateFile(disseminationAssuranceDashboardTemplate, translate);
    expect(file.name).toBe('dissemination-assurance.json');
    expect(JSON.parse(await file.text()).type).toBe('dashboard');
  });
});
