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

// One entity of the requirement on the threat map.
export interface IrThreatMapMarker {
  // The match id: a click opens the match drawer of the requirement.
  id: string;
  entityId: string;
  // Last fact that changed the entity in the requirement (the horizontal axis).
  date: string;
  score: number;
  name: string;
  type: string;
  // Number of criteria of the requirement the entity matches (why it is in).
  matchedCriteria: number;
}

// The fields of a requirement match the map reads (IrOverviewQuery carries them).
export interface IrThreatMapMatch {
  readonly id: string;
  readonly match_status: string;
  readonly match_excluded: boolean;
  readonly match_score: number;
  readonly match_entity_id: string;
  readonly match_entity_type: string;
  readonly match_entity_name?: string | null;
  readonly match_last_fact_at?: string | null;
  readonly match_criteria_ids: readonly string[];
  readonly entity?: { readonly representative: { readonly main: string } } | null;
}

// Filled shapes only: an outline shape (cross, plus, line) is unreadable at marker size.
export type IrThreatMapShape = 'circle' | 'square' | 'diamond' | 'triangle' | 'star';
export const IR_THREAT_MAP_SHAPES: IrThreatMapShape[] = ['circle', 'square', 'diamond', 'triangle', 'star'];

export interface IrThreatMapTypeStyle {
  color: string;
  shape: IrThreatMapShape;
}

// Time windows offered on the map, in days.
export const IR_THREAT_MAP_WINDOWS = [7, 30, 90] as const;
export type IrThreatMapWindow = typeof IR_THREAT_MAP_WINDOWS[number];

// Lower bound of the score bands offered on the map.
export const IR_THREAT_MAP_SCORE_BANDS = [0, 50, 75] as const;
export type IrThreatMapScoreBand = typeof IR_THREAT_MAP_SCORE_BANDS[number];

export const IR_THREAT_MAP_MIN_MARKER = 7;
export const IR_THREAT_MAP_MAX_MARKER = 20;

const DAY = 24 * 3600 * 1000;

/**
 * The entities of the requirement placed on the map: in the requirement (auto or accepted) or proposed,
 * still eligible, with a dated last fact inside the window. An entity without a dated fact has no place on
 * the time axis and is left out.
 */
export const toThreatMapMarkers = (
  matches: readonly IrThreatMapMatch[],
  days: number,
  now: number = Date.now(),
): IrThreatMapMarker[] => {
  const since = now - days * DAY;
  return matches
    .filter((m) => ['auto', 'accepted', 'proposed'].includes(m.match_status) && !m.match_excluded)
    .filter((m) => {
      if (!m.match_last_fact_at) return false;
      const time = new Date(m.match_last_fact_at).getTime();
      return !Number.isNaN(time) && time >= since && time <= now;
    })
    .map((m) => ({
      id: m.id,
      entityId: m.match_entity_id,
      date: m.match_last_fact_at as string,
      score: m.match_score,
      name: m.match_entity_name ?? m.entity?.representative.main ?? m.match_entity_id,
      type: m.match_entity_type,
      matchedCriteria: m.match_criteria_ids.length,
    }));
};

/**
 * One colour and one shape per entity type, so two types never look alike
 * (the family colour of itemColor gives every threat the same colour).
 * The types are sorted first: the legend and the map always agree.
 */
export const buildTypeStyles = (
  entityTypes: string[],
  palette: string[],
): Record<string, IrThreatMapTypeStyle> => {
  const sorted = [...new Set(entityTypes)].sort();
  return Object.fromEntries(sorted.map((type, index) => [type, {
    color: palette.length > 0 ? palette[index % palette.length] : '#888888',
    shape: IR_THREAT_MAP_SHAPES[index % IR_THREAT_MAP_SHAPES.length],
  }]));
};

/** Marker size grows with the number of entities a cluster holds, capped. */
export const markerSize = (clusterSize: number): number => Math.min(
  IR_THREAT_MAP_MAX_MARKER,
  IR_THREAT_MAP_MIN_MARKER + Math.round(3 * Math.sqrt(Math.max(0, clusterSize - 1))),
);

export type ApexIrThreatMapSeries = {
  name: string;
  data: [{
    x: number;
    y: number;
    fillColor: string;
    meta: {
      size: number;
      type: string;
      group: IrThreatMapMarker[];
    };
  }];
}[];
