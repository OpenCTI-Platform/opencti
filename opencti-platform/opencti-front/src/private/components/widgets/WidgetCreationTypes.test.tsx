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
  'bookmark',
  'wordcloud',
];

describe('getVisualizationTypes', () => {
  describe('when host is a workspace', () => {
    it('all visualization types but attribute or custom-attributes are available', () => {
      expect(getVisualizationTypes({
        kind: 'workspace',
      }, false).map(({ key }) => key)).toStrictEqual(ALL_VISUALIZATION_TYPES.filter((v) => v !== 'attribute' && v !== 'custom-attributes'));
    });
  });

  describe('when host is a fintel template', () => {
    it('only list visualization is available', () => {
      expect(getVisualizationTypes({
        kind: 'fintelTemplate',
        fintelEntityType: 'Report',
        fintelWidgets: [],
        fintelEditorValue: '',
      }, false).map(({ key }) => key)).toStrictEqual(['list']);
    });
  });

  describe('when host is a custom view', () => {
    it('all visualization types but attribute are available when feature flag is enabled', () => {
      expect(getVisualizationTypes({
        kind: 'custom-view',
        customViewTargetEntityType: 'Malware',
      }, true).map(({ key }) => key)).toStrictEqual(ALL_VISUALIZATION_TYPES.filter((v) => v !== 'attribute'));
    });

    it('custom-attributes is not available when feature flag is disabled', () => {
      expect(getVisualizationTypes({
        kind: 'custom-view',
        customViewTargetEntityType: 'Malware',
      }, false).map(({ key }) => key)).toStrictEqual(ALL_VISUALIZATION_TYPES.filter((v) => v !== 'attribute' && v !== 'custom-attributes'));
    });
  });
});
