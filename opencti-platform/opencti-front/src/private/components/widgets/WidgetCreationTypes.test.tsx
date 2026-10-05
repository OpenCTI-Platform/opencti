import { describe, it, expect } from 'vitest';
import { getVisualizationTypes } from './WidgetCreationTypes';

const ALL_VISUALIZATION_TYPES = [
  'custom-attributes',
  'attribute',
  'text',
  'knowledge-health-score',
  'knowledge-health-trend',
  'curation-open-proposals',
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
  'defense-tactic-coverage',
  'defense-top-gaps',
  'defense-levels',
  'hunt-hits-over-time',
  'hunt-runs-per-platform',
  'hunt-verdict-distribution',
  'bubble',
];

const DEFENSE_VISUALIZATION_TYPES = ['defense-tactic-coverage', 'defense-top-gaps', 'defense-levels'];
const CURATION_VISUALIZATION_TYPES = ['knowledge-health-score', 'knowledge-health-trend', 'curation-open-proposals'];
const HUNT_VISUALIZATION_TYPES = ['hunt-hits-over-time', 'hunt-runs-per-platform', 'hunt-verdict-distribution'];

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
    it('all visualization types but attribute, bubble and the platform-wide defense, curation and hunt ones are available (custom-attributes always included)', () => {
      // The bubble chart only renders the Intelligence sources perspective, which custom views do not offer
      expect(getVisualizationTypes({
        kind: 'custom-view',
        customViewTargetEntityType: 'Malware',
      }).map(({ key }) => key)).toStrictEqual(
        ALL_VISUALIZATION_TYPES.filter((v) => v !== 'attribute' && v !== 'bubble' && !DEFENSE_VISUALIZATION_TYPES.includes(v) && !CURATION_VISUALIZATION_TYPES.includes(v) && !HUNT_VISUALIZATION_TYPES.includes(v)),
      );
    });
  });
});
