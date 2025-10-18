import { describe, it, expect } from 'vitest';
import {
  getCurrentCategory,
  getCurrentAvailableParameters,
  getCurrentDataSelectionLimit,
  getCurrentIsRelationships,
  isWidgetListOrTimeline,
  isDataSelectionNumberValid,
  isWidgetUsingRelationsAggregation,
  WidgetVisualizationTypes,
  workspacesWidgetVisualizationTypes,
  fintelTemplatesWidgetVisualizationTypes,
} from './widgetUtils';
import type { WidgetDataSelection } from './widget';

describe('widgetUtils', () => {
  describe('getCurrentCategory', () => {
    it('should return "none" for null type', () => {
      expect(getCurrentCategory(null)).toBe('none');
    });

    it('should return "none" for empty string', () => {
      expect(getCurrentCategory('')).toBe('none');
    });

    it('should return correct category for valid widget types', () => {
      expect(getCurrentCategory('attribute')).toBe('attribute');
      expect(getCurrentCategory('text')).toBe('text');
      expect(getCurrentCategory('number')).toBe('number');
      expect(getCurrentCategory('list')).toBe('list');
      expect(getCurrentCategory('distribution-list')).toBe('distribution');
      expect(getCurrentCategory('vertical-bar')).toBe('timeseries');
      expect(getCurrentCategory('line')).toBe('timeseries');
      expect(getCurrentCategory('area')).toBe('timeseries');
      expect(getCurrentCategory('timeline')).toBe('list');
      expect(getCurrentCategory('donut')).toBe('distribution');
      expect(getCurrentCategory('horizontal-bar')).toBe('distribution');
      expect(getCurrentCategory('radar')).toBe('distribution');
      expect(getCurrentCategory('polar-area')).toBe('distribution');
      expect(getCurrentCategory('heatmap')).toBe('timeseries');
      expect(getCurrentCategory('tree')).toBe('distribution');
      expect(getCurrentCategory('map')).toBe('distribution');
      expect(getCurrentCategory('bookmark')).toBe('timeseries');
      expect(getCurrentCategory('wordcloud')).toBe('distribution');
    });

    it('should return "none" for invalid widget type', () => {
      expect(getCurrentCategory('invalid-type')).toBe('none');
    });
  });

  describe('getCurrentAvailableParameters', () => {
    it('should return empty array for null type', () => {
      expect(getCurrentAvailableParameters(null)).toEqual([]);
    });

    it('should return empty array for empty string', () => {
      expect(getCurrentAvailableParameters('')).toEqual([]);
    });

    it('should return empty array for types with no parameters', () => {
      expect(getCurrentAvailableParameters('attribute')).toEqual([]);
      expect(getCurrentAvailableParameters('text')).toEqual([]);
      expect(getCurrentAvailableParameters('number')).toEqual([]);
      expect(getCurrentAvailableParameters('list')).toEqual([]);
      expect(getCurrentAvailableParameters('timeline')).toEqual([]);
      expect(getCurrentAvailableParameters('heatmap')).toEqual([]);
      expect(getCurrentAvailableParameters('bookmark')).toEqual([]);
    });

    it('should return correct parameters for types with single parameter', () => {
      expect(getCurrentAvailableParameters('distribution-list')).toEqual(['attribute']);
      expect(getCurrentAvailableParameters('donut')).toEqual(['attribute']);
      expect(getCurrentAvailableParameters('horizontal-bar')).toEqual(['attribute']);
      expect(getCurrentAvailableParameters('radar')).toEqual(['attribute']);
      expect(getCurrentAvailableParameters('polar-area')).toEqual(['attribute']);
      expect(getCurrentAvailableParameters('map')).toEqual(['attribute']);
      expect(getCurrentAvailableParameters('wordcloud')).toEqual(['attribute']);
      expect(getCurrentAvailableParameters('line')).toEqual(['legend']);
    });

    it('should return correct parameters for types with multiple parameters', () => {
      expect(getCurrentAvailableParameters('vertical-bar')).toEqual(['stacked', 'legend']);
      expect(getCurrentAvailableParameters('area')).toEqual(['stacked', 'legend']);
      expect(getCurrentAvailableParameters('tree')).toEqual(['attribute', 'distributed']);
    });

    it('should return a mutable array (not readonly)', () => {
      const params = getCurrentAvailableParameters('vertical-bar');
      expect(() => {
        params.push('test');
      }).not.toThrow();
    });

    it('should return empty array for invalid widget type', () => {
      expect(getCurrentAvailableParameters('invalid-type')).toEqual([]);
    });
  });

  describe('getCurrentDataSelectionLimit', () => {
    it('should return 0 for empty string', () => {
      expect(getCurrentDataSelectionLimit('')).toBe(0);
    });

    it('should return 0 for types with undefined limit', () => {
      expect(getCurrentDataSelectionLimit('attribute')).toBe(0);
      expect(getCurrentDataSelectionLimit('text')).toBe(0);
    });

    it('should return 1 for single selection types', () => {
      expect(getCurrentDataSelectionLimit('number')).toBe(1);
      expect(getCurrentDataSelectionLimit('list')).toBe(1);
      expect(getCurrentDataSelectionLimit('distribution-list')).toBe(1);
      expect(getCurrentDataSelectionLimit('timeline')).toBe(1);
      expect(getCurrentDataSelectionLimit('donut')).toBe(1);
      expect(getCurrentDataSelectionLimit('radar')).toBe(1);
      expect(getCurrentDataSelectionLimit('polar-area')).toBe(1);
      expect(getCurrentDataSelectionLimit('tree')).toBe(1);
      expect(getCurrentDataSelectionLimit('map')).toBe(1);
      expect(getCurrentDataSelectionLimit('bookmark')).toBe(1);
      expect(getCurrentDataSelectionLimit('wordcloud')).toBe(1);
    });

    it('should return 2 for horizontal-bar', () => {
      expect(getCurrentDataSelectionLimit('horizontal-bar')).toBe(2);
    });

    it('should return 5 for multiple selection types', () => {
      expect(getCurrentDataSelectionLimit('vertical-bar')).toBe(5);
      expect(getCurrentDataSelectionLimit('line')).toBe(5);
      expect(getCurrentDataSelectionLimit('area')).toBe(5);
      expect(getCurrentDataSelectionLimit('heatmap')).toBe(5);
    });

    it('should return 0 for invalid widget type', () => {
      expect(getCurrentDataSelectionLimit('invalid-type')).toBe(0);
    });
  });

  describe('getCurrentIsRelationships', () => {
    it('should return false for empty string', () => {
      expect(getCurrentIsRelationships('')).toBe(false);
    });

    it('should return true for all relationship-supporting widgets', () => {
      expect(getCurrentIsRelationships('attribute')).toBe(true);
      expect(getCurrentIsRelationships('number')).toBe(true);
      expect(getCurrentIsRelationships('list')).toBe(true);
      expect(getCurrentIsRelationships('distribution-list')).toBe(true);
      expect(getCurrentIsRelationships('vertical-bar')).toBe(true);
      expect(getCurrentIsRelationships('line')).toBe(true);
      expect(getCurrentIsRelationships('area')).toBe(true);
      expect(getCurrentIsRelationships('timeline')).toBe(true);
      expect(getCurrentIsRelationships('donut')).toBe(true);
      expect(getCurrentIsRelationships('horizontal-bar')).toBe(true);
      expect(getCurrentIsRelationships('radar')).toBe(true);
      expect(getCurrentIsRelationships('polar-area')).toBe(true);
      expect(getCurrentIsRelationships('heatmap')).toBe(true);
      expect(getCurrentIsRelationships('tree')).toBe(true);
      expect(getCurrentIsRelationships('map')).toBe(true);
      expect(getCurrentIsRelationships('wordcloud')).toBe(true);
    });

    it('should return false for non-relationship widgets', () => {
      expect(getCurrentIsRelationships('text')).toBe(false);
      expect(getCurrentIsRelationships('bookmark')).toBe(false);
    });

    it('should return false for invalid widget type', () => {
      expect(getCurrentIsRelationships('invalid-type')).toBe(false);
    });
  });

  describe('isWidgetListOrTimeline', () => {
    it('should return true for list widget', () => {
      expect(isWidgetListOrTimeline('list')).toBe(true);
    });

    it('should return true for timeline widget', () => {
      expect(isWidgetListOrTimeline('timeline')).toBe(true);
    });

    it('should return false for other widget types', () => {
      expect(isWidgetListOrTimeline('number')).toBe(false);
      expect(isWidgetListOrTimeline('donut')).toBe(false);
      expect(isWidgetListOrTimeline('text')).toBe(false);
      expect(isWidgetListOrTimeline('vertical-bar')).toBe(false);
    });

    it('should return false for empty string', () => {
      expect(isWidgetListOrTimeline('')).toBe(false);
    });

    it('should return false for invalid widget type', () => {
      expect(isWidgetListOrTimeline('invalid-type')).toBe(false);
    });
  });

  describe('isDataSelectionNumberValid', () => {
    const createDataSelection = (number: number): WidgetDataSelection[] => [
      {
        number,
        perspective: 'entities',
        filters: null,
      },
    ];

    it('should return true for widgets without number restrictions', () => {
      expect(isDataSelectionNumberValid('number', createDataSelection(150))).toBe(true);
      expect(isDataSelectionNumberValid('text', createDataSelection(150))).toBe(true);
      expect(isDataSelectionNumberValid('vertical-bar', createDataSelection(150))).toBe(true);
      expect(isDataSelectionNumberValid('line', createDataSelection(150))).toBe(true);
      expect(isDataSelectionNumberValid('area', createDataSelection(150))).toBe(true);
      expect(isDataSelectionNumberValid('heatmap', createDataSelection(150))).toBe(true);
      expect(isDataSelectionNumberValid('bookmark', createDataSelection(150))).toBe(true);
    });

    it('should return true for widgets with number <= 100', () => {
      expect(isDataSelectionNumberValid('list', createDataSelection(100))).toBe(true);
      expect(isDataSelectionNumberValid('distribution-list', createDataSelection(50))).toBe(true);
      expect(isDataSelectionNumberValid('donut', createDataSelection(10))).toBe(true);
      expect(isDataSelectionNumberValid('horizontal-bar', createDataSelection(1))).toBe(true);
      expect(isDataSelectionNumberValid('radar', createDataSelection(25))).toBe(true);
      expect(isDataSelectionNumberValid('polar-area', createDataSelection(75))).toBe(true);
      expect(isDataSelectionNumberValid('tree', createDataSelection(100))).toBe(true);
      expect(isDataSelectionNumberValid('map', createDataSelection(99))).toBe(true);
      expect(isDataSelectionNumberValid('wordcloud', createDataSelection(50))).toBe(true);
    });

    it('should return true for list widget with number <= 500', () => {
      expect(isDataSelectionNumberValid('list', createDataSelection(500))).toBe(true);
    });

    it('should return false for restricted widgets with number > 100', () => {
      expect(isDataSelectionNumberValid('distribution-list', createDataSelection(150))).toBe(false);
      expect(isDataSelectionNumberValid('donut', createDataSelection(200))).toBe(false);
      expect(isDataSelectionNumberValid('horizontal-bar', createDataSelection(101))).toBe(false);
      expect(isDataSelectionNumberValid('radar', createDataSelection(500))).toBe(false);
      expect(isDataSelectionNumberValid('polar-area', createDataSelection(101))).toBe(false);
      expect(isDataSelectionNumberValid('tree', createDataSelection(150))).toBe(false);
      expect(isDataSelectionNumberValid('map', createDataSelection(101))).toBe(false);
      expect(isDataSelectionNumberValid('wordcloud', createDataSelection(250))).toBe(false);
    });

    it('should return true when number is undefined', () => {
      const dataSelection: WidgetDataSelection[] = [{
        number: undefined,
        perspective: 'entities',
        filters: null,
      }];
      expect(isDataSelectionNumberValid('list', dataSelection)).toBe(true);
      expect(isDataSelectionNumberValid('donut', dataSelection)).toBe(true);
    });

    it('should validate all data selections in array', () => {
      const mixedDataSelection: WidgetDataSelection[] = [
        { number: 50, perspective: 'entities', filters: null },
        { number: 501, perspective: 'relationships', filters: null },
      ];
      expect(isDataSelectionNumberValid('list', mixedDataSelection)).toBe(false);

      const validDataSelection: WidgetDataSelection[] = [
        { number: 50, perspective: 'entities', filters: null },
        { number: 100, perspective: 'relationships', filters: null },
      ];
      expect(isDataSelectionNumberValid('list', validDataSelection)).toBe(true);
    });
  });

  describe('isWidgetUsingRelationsAggregation', () => {
    it('should return true for widgets using relations aggregation', () => {
      const typesWithAggregation: WidgetVisualizationTypes[] = [
        'wordcloud',
        'map',
        'radar',
        'polar-area',
        'horizontal-bar',
        'donut',
        'distribution-list',
        'tree',
      ];

      typesWithAggregation.forEach((type) => {
        expect(isWidgetUsingRelationsAggregation(type)).toBe(true);
      });
    });

    it('should return false for widgets not using relations aggregation', () => {
      const typesWithoutAggregation: WidgetVisualizationTypes[] = [
        'attribute',
        'text',
        'number',
        'list',
        'vertical-bar',
        'line',
        'area',
        'timeline',
        'heatmap',
        'bookmark',
      ];

      typesWithoutAggregation.forEach((type) => {
        expect(isWidgetUsingRelationsAggregation(type)).toBe(false);
      });
    });
  });

  describe('workspacesWidgetVisualizationTypes', () => {
    it('should include all other widget types', () => {
      expect(workspacesWidgetVisualizationTypes.length).toBeGreaterThan(15);
      const hasText = workspacesWidgetVisualizationTypes.some((w) => w.key === 'text');
      const hasList = workspacesWidgetVisualizationTypes.some((w) => w.key === 'list');
      const hasDonut = workspacesWidgetVisualizationTypes.some((w) => w.key === 'donut');
      expect(hasText).toBe(true);
      expect(hasList).toBe(true);
      expect(hasDonut).toBe(true);
    });
  });

  describe('fintelTemplatesWidgetVisualizationTypes', () => {
    it('should only include list widget', () => {
      expect(fintelTemplatesWidgetVisualizationTypes.length).toBe(1);
      expect(fintelTemplatesWidgetVisualizationTypes[0].key).toBe('list');
    });
  });

  describe('Type safety with as const', () => {
    it('should export valid WidgetVisualizationTypes', () => {
      const validTypes: WidgetVisualizationTypes[] = [
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

      expect(validTypes.length).toBe(18);
    });
  });
});
