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
  'case-timeline',
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

  describe('when host is a custom view', () => {
    it('all visualization types but attribute are available (custom-attributes always included)', () => {
      expect(getVisualizationTypes({
        kind: 'custom-view',
        customViewTargetEntityType: 'Malware',
      }).map(({ key }) => key)).toStrictEqual(
        ALL_VISUALIZATION_TYPES.filter((v) => v !== 'attribute' && v !== 'case-timeline'),
      );
    });

    it('the case timeline is only available on the custom views of incidents and cases', () => {
      ['Incident', 'Case-Incident', 'Case-Rfi', 'Case-Rft'].forEach((entityType) => {
        expect(getVisualizationTypes({
          kind: 'custom-view',
          customViewTargetEntityType: entityType,
        }).map(({ key }) => key)).toContain('case-timeline');
      });
    });
  });
});
