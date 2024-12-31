import * as R from 'ramda';

export const widgetVisualizationTypes = [
  {
    key: 'text',
    name: 'Text',
    category: 'text',
    availableParameters: [],
    isRelationships: false,
    isEntities: false,
    isAudits: false,
  },
  {
    key: 'number',
    name: 'Number',
    dataSelectionLimit: 1,
    category: 'number',
    availableParameters: [],
    isRelationships: true,
    isEntities: true,
    isAudits: true,
  },
  {
    key: 'list',
    name: 'List',
    dataSelectionLimit: 1,
    category: 'list',
    availableParameters: [],
    isRelationships: true,
    isEntities: true,
    isAudits: true,
  },
  {
    key: 'distribution-list',
    name: 'List (distribution)',
    dataSelectionLimit: 1,
    category: 'distribution',
    availableParameters: ['attribute'],
    isRelationships: true,
    isEntities: true,
    isAudits: true,
  },
  {
    key: 'vertical-bar',
    name: 'Vertical Bar',
    dataSelectionLimit: 5,
    category: 'timeseries',
    availableParameters: ['stacked', 'legend'],
    isRelationships: true,
    isEntities: true,
    isAudits: true,
  },
  {
    key: 'line',
    name: 'Line',
    dataSelectionLimit: 5,
    category: 'timeseries',
    availableParameters: ['legend'],
    isRelationships: true,
    isEntities: true,
    isAudits: true,
  },
  {
    key: 'area',
    name: 'Area',
    dataSelectionLimit: 5,
    category: 'timeseries',
    availableParameters: ['stacked', 'legend'],
    isRelationships: true,
    isEntities: true,
    isAudits: true,
  },
  {
    key: 'timeline',
    name: 'Timeline',
    dataSelectionLimit: 1,
    category: 'list',
    availableParameters: [],
    isRelationships: true,
    isEntities: true,
    isAudits: false,
  },
  {
    key: 'donut',
    name: 'Donut',
    dataSelectionLimit: 1,
    category: 'distribution',
    availableParameters: ['attribute'],
    isRelationships: true,
    isEntities: true,
    isAudits: true,
  },
  {
    key: 'horizontal-bar',
    name: 'Horizontal Bar',
    dataSelectionLimit: 2,
    category: 'distribution',
    availableParameters: ['attribute'],
    isRelationships: true,
    isEntities: true,
    isAudits: true,
  },
  {
    key: 'radar',
    name: 'Radar',
    dataSelectionLimit: 1,
    category: 'distribution',
    availableParameters: ['attribute'],
    isRelationships: true,
    isEntities: true,
    isAudits: true,
  },
  {
    key: 'polar-area',
    name: 'Polar Area',
    dataSelectionLimit: 1,
    category: 'distribution',
    availableParameters: ['attribute'],
    isRelationships: true,
    isEntities: true,
    isAudits: true,
  },
  {
    key: 'heatmap',
    name: 'Heatmap',
    dataSelectionLimit: 5,
    category: 'timeseries',
    availableParameters: [],
    isRelationships: true,
    isEntities: true,
    isAudits: true,
  },
  {
    key: 'tree',
    name: 'Tree',
    dataSelectionLimit: 1,
    category: 'distribution',
    availableParameters: ['attribute', 'distributed'],
    isRelationships: true,
    isEntities: true,
    isAudits: true,
  },
  {
    key: 'map',
    name: 'Map',
    dataSelectionLimit: 1,
    category: 'distribution',
    availableParameters: ['attribute'],
    isRelationships: true,
    isEntities: false,
    isAudits: false,
  },
  {
    key: 'bookmark',
    name: 'Bookmark',
    dataSelectionLimit: 1,
    category: 'timeseries',
    availableParameters: [],
    isRelationships: false,
    isEntities: true,
    isAudits: false,
  },
  {
    key: 'wordcloud',
    name: 'Word Cloud',
    dataSelectionLimit: 1,
    category: 'distribution',
    availableParameters: ['attribute'],
    isRelationships: true,
    isEntities: true,
    isAudits: true,
  },
];

export const indexedVisualizationTypes = R.indexBy(R.prop('key'), widgetVisualizationTypes);

export const getCurrentCategory = (type: string | null) => {
  if (!type) return 'none';
  return indexedVisualizationTypes[type]?.category ?? 'none';
};
export const getCurrentAvailableParameters = (type: string | null): string[] => {
  if (!type) return [];
  return indexedVisualizationTypes[type]?.availableParameters ?? [];
};
export const getCurrentDataSelectionLimit = (type: string) => {
  return indexedVisualizationTypes[type]?.dataSelectionLimit ?? 0;
};
export const getCurrentIsRelationships = (type: string) => {
  return indexedVisualizationTypes[type]?.isRelationships ?? false;
};
export const isWidgetListOrTimeline = (type: string) => {
  return indexedVisualizationTypes[type]?.key === 'list' || indexedVisualizationTypes[type]?.key === 'timeline';
};
