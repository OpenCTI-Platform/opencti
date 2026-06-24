import { describe, it, expect } from 'vitest';
import { getVisualizationTypes } from './WidgetCreationTypes';

const ALL_VISUALIZATION_TYPES = [
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
    it('all visualization types but attribute are available', () => {
      expect(getVisualizationTypes({
        kind: 'workspace',
      }).map(({ key }) => key)).toStrictEqual(ALL_VISUALIZATION_TYPES.filter((v) => v !== 'attribute'));
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

  describe('when host is a custom view', () => {
    it('all visualization types but attribute are available', () => {
      expect(getVisualizationTypes({
        kind: 'custom-view',
        customViewTargetEntityType: 'Malware',
      }).map(({ key }) => key)).toStrictEqual(ALL_VISUALIZATION_TYPES.filter((v) => v !== 'attribute'));
    });
  });
});
