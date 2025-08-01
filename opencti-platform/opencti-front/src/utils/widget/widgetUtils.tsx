import * as R from 'ramda';
import { FormatShapesOutlined, MapOutlined, PieChartOutlined, ViewQuiltOutlined } from '@mui/icons-material';
import {
  AlignHorizontalLeft,
  ChartAreasplineVariant,
  ChartBar,
  ChartBubble,
  ChartDonut,
  ChartLine,
  ChartTimeline,
  ChartTree,
  Counter,
  FormatListNumberedRtl,
  Radar,
  StarSettingsOutline,
  TagTextOutline,
  ViewListOutline,
} from 'mdi-material-ui';
import React from 'react';
// eslint-disable-next-line import/extensions
import type { WidgetDataSelection } from './widget';

const widgetVisualizationTypes = [
  {
    key: 'attribute',
    name: 'Attribute',
    category: 'attribute',
    availableParameters: [],
    isRelationships: true,
    isEntities: true,
    isAudits: false,
  },
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
    availableParameters: ['uniqueUsers', 'intervalUniqueUsers'],
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
    availableParameters: ['stacked', 'legend', 'uniqueUsers', 'intervalUniqueUsers'],
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

export const workspacesWidgetVisualizationTypes = widgetVisualizationTypes.filter((w) => w.key !== 'attribute');

export const fintelTemplatesWidgetVisualizationTypes = widgetVisualizationTypes.filter((w) => ['list'].includes(w.key));

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

export const renderWidgetIcon = (key: string, fontSize: 'large' | 'small' | 'medium') => {
  switch (key) {
    case 'attribute':
      return <TagTextOutline fontSize={fontSize} color="primary"/>;
    case 'map':
      return <MapOutlined fontSize={fontSize} color="primary"/>;
    case 'horizontal-bar':
      return <AlignHorizontalLeft fontSize={fontSize} color="primary"/>;
    case 'vertical-bar':
      return <ChartBar fontSize={fontSize} color="primary"/>;
    case 'donut':
      return <ChartDonut fontSize={fontSize} color="primary"/>;
    case 'area':
      return <ChartAreasplineVariant fontSize={fontSize} color="primary"/>;
    case 'timeline':
      return <ChartTimeline fontSize={fontSize} color="primary"/>;
    case 'list':
      return <ViewListOutline fontSize={fontSize} color="primary"/>;
    case 'distribution-list':
      return <FormatListNumberedRtl fontSize={fontSize} color="primary"/>;
    case 'number':
      return <Counter fontSize={fontSize} color="primary"/>;
    case 'text':
      return <FormatShapesOutlined fontSize={fontSize} color="primary"/>;
    case 'heatmap':
      return <ChartBubble fontSize={fontSize} color="primary"/>;
    case 'line':
      return <ChartLine fontSize={fontSize} color="primary"/>;
    case 'radar':
      return <Radar fontSize={fontSize} color="primary"/>;
    case 'polar-area':
      return <PieChartOutlined fontSize={fontSize} color="primary"/>;
    case 'tree':
      return <ChartTree fontSize={fontSize} color="primary"/>;
    case 'bookmark':
      return <StarSettingsOutline fontSize={fontSize} color="primary"/>;
    case 'wordcloud':
      return <ViewQuiltOutlined fontSize={fontSize} color="primary"/>;
    default:
      return <div />;
  }
};

export const isDataSelectionNumberValid = (type: string, dataSelection: WidgetDataSelection[]) => {
  if (type === 'list'
    || type === 'distribution-list'
    || type === 'timeline'
    || type === 'donut'
    || type === 'horizontal-bar'
    || type === 'radar'
    || type === 'polar-area'
    || type === 'tree'
    || type === 'map'
    || type === 'wordcloud'
  ) {
    return dataSelection.every((selection) => !selection.number || selection.number <= 100);
  }
  return true;
};
