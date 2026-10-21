import { describe, expect, it } from 'vitest';
import { buildSectorBenchmarkDashboard, lockedSectorBenchmarkWidgets } from './threatPulseDashboardTemplate';
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
    // One title per widget: the template card lists them
    expect(new Set(widgets.map((widget) => widget.parameters?.title)).size).toBe(widgets.length);
  });

  it('should leave out the widgets of the full experience in preview and name them', () => {
    const previewWidgets = Object.values(buildSectorBenchmarkDashboard(translate, { preview: true }).widgets);
    expect(previewWidgets.map((widget) => widget.type)).toEqual(['pulse-trending', 'pulse-benchmark', 'number', 'donut', 'horizontal-bar']);
    expect(lockedSectorBenchmarkWidgets(translate)).toEqual([
      '[Threats with a rising sector trend]',
      '[Latest threats with a rising sector trend]',
      '[Indicators per week of network first seen]',
    ]);
    // Every widget read in preview has a value there: none reads the sector trend or the network first seen
    previewWidgets.forEach((widget) => {
      expect(JSON.stringify(widget.dataSelection)).not.toMatch(/pulse_sector_trend|pulse_first_seen_network/);
    });
  });

  it('should name no period in its titles and order the list it titles as the latest', () => {
    // The dashboard dates bound the objects by their creation, not the period of a community statistic
    widgets.forEach((widget) => expect(widget.parameters?.title).not.toMatch(/week]|days]|this week|last \d+ days|Top \d+/));
    const list = widgets.find((widget) => widget.type === 'list');
    expect(list?.parameters?.title).toBe('[Latest threats with a rising sector trend]');
    expect(list?.dataSelection[0]).toMatchObject({ number: 10, sort_by: 'created_at', sort_mode: 'desc' });
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
