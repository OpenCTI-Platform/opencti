/*
Copyright (c) 2021-2025 Filigran SAS

This file is part of the OpenCTI Enterprise Edition ("EE") and is
licensed under the OpenCTI Enterprise Edition License (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

https://github.com/OpenCTI-Platform/opencti/blob/master/LICENSE

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*/

export interface PirThreatMapMarker {
  id: string;
  date: string;
  score: number;
  name: string;
  type: string;
  // Number of PIR criteria the entity matches (why it scores).
  matchedCriteria: number;
}

// Filled shapes only: an outline shape (cross, plus, line) is unreadable at marker size.
export type PirThreatMapShape = 'circle' | 'square' | 'diamond' | 'triangle' | 'star';
export const PIR_THREAT_MAP_SHAPES: PirThreatMapShape[] = ['circle', 'square', 'diamond', 'triangle', 'star'];

export interface PirThreatMapTypeStyle {
  color: string;
  shape: PirThreatMapShape;
}

// Time windows offered on the map, in days.
export const PIR_THREAT_MAP_WINDOWS = [7, 30, 90] as const;
export type PirThreatMapWindow = typeof PIR_THREAT_MAP_WINDOWS[number];

// Lower bound of the score bands offered on the map.
export const PIR_THREAT_MAP_SCORE_BANDS = [0, 50, 75] as const;
export type PirThreatMapScoreBand = typeof PIR_THREAT_MAP_SCORE_BANDS[number];

export const PIR_THREAT_MAP_MIN_MARKER = 7;
export const PIR_THREAT_MAP_MAX_MARKER = 20;

/**
 * One colour and one shape per entity type, so two types never look alike
 * (the family colour of itemColor gives every threat the same colour).
 * The types are sorted first: the legend and the map always agree.
 */
export const buildTypeStyles = (
  entityTypes: string[],
  palette: string[],
): Record<string, PirThreatMapTypeStyle> => {
  const sorted = [...new Set(entityTypes)].sort();
  return Object.fromEntries(sorted.map((type, index) => [type, {
    color: palette.length > 0 ? palette[index % palette.length] : '#888888',
    shape: PIR_THREAT_MAP_SHAPES[index % PIR_THREAT_MAP_SHAPES.length],
  }]));
};

/** Marker size grows with the number of entities a cluster holds, capped. */
export const markerSize = (clusterSize: number): number => Math.min(
  PIR_THREAT_MAP_MAX_MARKER,
  PIR_THREAT_MAP_MIN_MARKER + Math.round(3 * Math.sqrt(Math.max(0, clusterSize - 1))),
);

export type ApexPirThreatMapSeries = {
  name: string;
  data: [{
    x: number;
    y: number;
    fillColor: string;
    meta: {
      size: number;
      type: string;
      group: PirThreatMapMarker[];
    };
  }];
}[];
