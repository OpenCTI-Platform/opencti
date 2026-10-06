import { describe, expect, it } from 'vitest';
import { fromB64 } from '../../../utils/String';
import { indexedVisualizationTypes } from '../../../utils/widget/widgetUtils';
import { buildDashboardTemplateExport, DASHBOARD_TEMPLATES } from './dashboardTemplates';
import { defenseCoverageDashboardTemplate, RULE_PATTERN_TYPES } from './defenseCoverageDashboardTemplate';

const translate = (text: string) => `[${text}]`;

interface ExportedWidget {
  id: string;
  type: string;
  perspective: string | null;
  parameters: { title: string };
  dataSelection: { attribute: string; filters: { filters: unknown[] } }[];
  layout: { i: string; x: number; w: number };
}

describe('defense coverage dashboard template', () => {
  const exported = buildDashboardTemplateExport(defenseCoverageDashboardTemplate, translate);
  const manifest: { widgets: Record<string, ExportedWidget> } = JSON.parse(fromB64(exported.configuration.manifest));
  const widgets = Object.values(manifest.widgets);

  it('counts every rule pattern type of the detection layer as a detection rule', () => {
    const ruleFilters = widgets
      .flatMap((widget) => widget.dataSelection)
      .flatMap((selection) => selection.filters.filters as { key: string[]; values: string[] }[])
      .filter((filter) => filter.key.includes('pattern_type'));
    expect(ruleFilters.length).toBeGreaterThan(0);
    ruleFilters.forEach((filter) => {
      expect(filter.values).toEqual(RULE_PATTERN_TYPES);
      expect(filter.values).toEqual(expect.arrayContaining(['elastic-rule', 'sentinel-rule', 'splunk-rule', 'tanium-signal', 'nova']));
    });
  });

  it('is offered in the template menu under its translated name', () => {
    expect(DASHBOARD_TEMPLATES).toContain(defenseCoverageDashboardTemplate);
    expect(exported.configuration.name).toBe('[Defense coverage]');
  });

  it('indexes every widget by its id and layout key', () => {
    expect(widgets).toHaveLength(5);
    Object.entries(manifest.widgets).forEach(([id, widget]) => {
      expect(widget.id).toBe(id);
      expect(widget.layout.i).toBe(id);
    });
  });

  it('only uses registered widget types, the defense ones without data selection', () => {
    widgets.forEach((widget) => expect(indexedVisualizationTypes[widget.type as keyof typeof indexedVisualizationTypes]).toBeDefined());
    const defenseWidgets = widgets.filter((widget) => widget.type.startsWith('defense-'));
    expect(defenseWidgets.map((widget) => widget.type)).toEqual(['defense-tactic-coverage', 'defense-top-gaps', 'defense-levels']);
    defenseWidgets.forEach((widget) => {
      expect(widget.perspective).toBeNull();
      expect(widget.dataSelection).toEqual([]);
    });
  });

  it('reads defense levels only through the defense widgets, never through attack pattern attributes', () => {
    const knowledgeWidgets = widgets.filter((widget) => !widget.type.startsWith('defense-'));
    expect(knowledgeWidgets.map((widget) => widget.type)).toEqual(['horizontal-bar', 'list']);
    knowledgeWidgets.forEach((widget) => {
      const filters = widget.dataSelection[0].filters.filters as { key: string[] }[];
      expect(filters).toContainEqual({ key: ['entity_type'], values: ['Indicator'], operator: 'eq', mode: 'or' });
      expect(filters.flatMap((filter) => filter.key).some((key) => key.includes('defense'))).toBe(false);
    });
  });

  it('gives the detection rule list the full width of the grid', () => {
    const list = widgets.find((widget) => widget.type === 'list');
    expect(list?.layout).toMatchObject({ x: 0, w: 12 });
  });

  it('translates every title', () => {
    widgets.forEach((widget) => expect(widget.parameters.title).toMatch(/^\[.+\]$/));
  });
});
