import { describe, it, expect } from 'vitest';
import { getVisualizationTypes } from './WidgetCreationTypes';

const ALL_VISUALIZATION_TYPES = [
  'custom-attributes',
  'attribute',
  'text',
  'number',
  'list',
  'distribution-list',
  'vertical-bar',
  'line',
  'area',
  'timeline',
  'donut',
  'horizontal-bar',
  'radar',
  'polar-area',
  'heatmap',
  'tree',
  'map',
  'provenance-freshness',
  'provenance-single-sourced',
  'bookmark',
  'wordcloud',
];

describe('getVisualizationTypes', () => {
  describe('when host is a workspace', () => {
    it('all visualization types but attribute or custom-attributes are available', () => {
      expect(getVisualizationTypes({
        kind: 'workspace',
      }).map(({ key }) => key)).toStrictEqual(
        ALL_VISUALIZATION_TYPES.filter((v) => v !== 'attribute' && v !== 'custom-attributes'),
      );
    });
  });

  describe('when host is a fintel template', () => {
    it('only list visualization is available', () => {
      expect(getVisualizationTypes({
        kind: 'fintelTemplate',
        fintelEntityType: 'Report',
        fintelWidgets: [],
        fintelEditorValue: '',
      }).map(({ key }) => key)).toStrictEqual(['list']);
    });
  });

  describe('when provenance is disabled on the platform', () => {
    it('the provenance widgets are not offered', () => {
      const keys = getVisualizationTypes({ kind: 'workspace' }, false).map(({ key }) => key);
      expect(keys).not.toContain('provenance-freshness');
      expect(keys).not.toContain('provenance-single-sourced');
      expect(keys).toContain('list');
    });
  });

  describe('when host is a custom view', () => {
    it('all visualization types but attribute are available (custom-attributes always included)', () => {
      expect(getVisualizationTypes({
        kind: 'custom-view',
        customViewTargetEntityType: 'Malware',
      }).map(({ key }) => key)).toStrictEqual(
        ALL_VISUALIZATION_TYPES.filter((v) => v !== 'attribute'),
      );
    });
  });
});
