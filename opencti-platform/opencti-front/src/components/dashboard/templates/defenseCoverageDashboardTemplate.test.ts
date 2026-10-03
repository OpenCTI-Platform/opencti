import { describe, expect, it } from 'vitest';
import { fromB64 } from '../../../utils/String';
import { indexedVisualizationTypes } from '../../../utils/widget/widgetUtils';
import { buildDashboardTemplateExport, DASHBOARD_TEMPLATES } from './dashboardTemplates';
import { defenseCoverageDashboardTemplate } from './defenseCoverageDashboardTemplate';

const translate = (text: string) => `[${text}]`;

interface ExportedWidget {
  id: string;
  type: string;
  perspective: string | null;
  parameters: { title: string };
  dataSelection: { attribute: string; filters: { filters: unknown[] } }[];
  layout: { i: string };
}

describe('defense coverage dashboard template', () => {
  const exported = buildDashboardTemplateExport(defenseCoverageDashboardTemplate, translate);
  const manifest: { widgets: Record<string, ExportedWidget> } = JSON.parse(fromB64(exported.configuration.manifest));
  const widgets = Object.values(manifest.widgets);

  it('is offered in the template menu under its translated name', () => {
    expect(DASHBOARD_TEMPLATES).toContain(defenseCoverageDashboardTemplate);
    expect(exported.configuration.name).toBe('[Defense coverage]');
  });

  it('indexes every widget by its id and layout key', () => {
    expect(widgets).toHaveLength(7);
    Object.entries(manifest.widgets).forEach(([id, widget]) => {
      expect(widget.id).toBe(id);
      expect(widget.layout.i).toBe(id);
    });
  });

  it('only uses registered widget types, the defense ones without data selection', () => {
    widgets.forEach((widget) => expect(indexedVisualizationTypes[widget.type as keyof typeof indexedVisualizationTypes]).toBeDefined());
    const defenseWidgets = widgets.filter((widget) => widget.type.startsWith('defense-'));
    expect(defenseWidgets.map((widget) => widget.type)).toEqual(['defense-tactic-coverage', 'defense-top-gaps']);
    defenseWidgets.forEach((widget) => {
      expect(widget.perspective).toBeNull();
      expect(widget.dataSelection).toEqual([]);
    });
  });

  it('queries the stored defense level of attack patterns', () => {
    const covered = widgets.find((widget) => widget.parameters.title === '[Techniques with a deployed detection]');
    const filters = covered?.dataSelection[0].filters.filters ?? [];
    expect(filters).toContainEqual({ key: ['entity_type'], values: ['Attack-Pattern'], operator: 'eq', mode: 'or' });
    expect(filters).toContainEqual({ key: ['defense_level'], values: ['3'], operator: 'gte', mode: 'or' });
    const distribution = widgets.find((widget) => widget.type === 'donut');
    expect(distribution?.dataSelection[0].attribute).toBe('defense_level');
  });

  it('translates every title', () => {
    widgets.forEach((widget) => expect(widget.parameters.title).toMatch(/^\[.+\]$/));
  });
});
