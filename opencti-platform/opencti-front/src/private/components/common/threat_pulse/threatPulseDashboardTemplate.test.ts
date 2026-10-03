import { describe, expect, it } from 'vitest';
import { buildSectorBenchmarkDashboard } from './threatPulseDashboardTemplate';
import { checkIfDateAttributeValid, indexedVisualizationTypes, isParametersOnlyWidget } from '../../../../utils/widget/widgetUtils';
import { deserializeDashboardManifestForFrontend, serializeDashboardManifestForBackend } from '../../../../components/dashboard/dashboard-utils';

const translate = (key: string) => `[${key}]`;

describe('Sector benchmark dashboard template', () => {
  const manifest = buildSectorBenchmarkDashboard(translate);
  const widgets = Object.values(manifest.widgets);

  it('should hold the two Threat Pulse widgets and the knowledge widgets on the community signal', () => {
    expect(widgets.map((widget) => widget.type)).toEqual(['pulse-trending', 'pulse-benchmark', 'number', 'number', 'donut', 'horizontal-bar', 'list', 'line']);
    widgets.forEach((widget) => expect(Object.keys(indexedVisualizationTypes)).toContain(widget.type));
  });

  it('should give every widget a translated title and a layout keyed by its id', () => {
    widgets.forEach((widget) => {
      expect(manifest.widgets[widget.id]).toBe(widget);
      expect(widget.layout.i).toBe(widget.id);
      expect(widget.parameters?.title).toMatch(/^\[.+\]$/);
      expect(widget.layout.x + widget.layout.w).toBeLessThanOrEqual(12);
    });
  });

  it('should configure the Threat Pulse widgets with parameters only', () => {
    widgets.filter((widget) => isParametersOnlyWidget(widget.type)).forEach((widget) => {
      expect(widget.dataSelection).toEqual([]);
      expect(widget.perspective).toBeNull();
    });
  });

  it('should only filter and aggregate on the Threat Pulse attributes of the scoped types', () => {
    const knowledge = widgets.filter((widget) => !isParametersOnlyWidget(widget.type));
    knowledge.forEach((widget) => {
      expect(widget.perspective).toBe('entities');
      expect(checkIfDateAttributeValid(widget.dataSelection)).toBe(true);
      widget.dataSelection.forEach((selection) => {
        const keys = selection.filters?.filters.map((filter) => filter.key) ?? [];
        expect(keys[0]).toBe('entity_type');
        keys.slice(1).forEach((key) => expect(key).toMatch(/^pulse_/));
      });
    });
    expect(knowledge.find((widget) => widget.type === 'donut')?.dataSelection[0].attribute).toBe('pulse_prevalence');
    expect(knowledge.find((widget) => widget.type === 'line')?.dataSelection[0].date_attribute).toBe('pulse_first_seen_network');
  });

  it('should survive the round trip through the backend manifest encoding', () => {
    const decoded = deserializeDashboardManifestForFrontend(serializeDashboardManifestForBackend(manifest));
    expect(Object.keys(decoded.widgets)).toEqual(Object.keys(manifest.widgets));
    expect(decoded.widgets[widgets[2].id].dataSelection[0].filters?.filters[1]).toMatchObject({ key: 'pulse_trend', values: ['rising'] });
  });

  it('should draw fresh widget ids on every creation', () => {
    const other = buildSectorBenchmarkDashboard(translate);
    expect(Object.keys(other.widgets).some((id) => manifest.widgets[id])).toBe(false);
  });
});
