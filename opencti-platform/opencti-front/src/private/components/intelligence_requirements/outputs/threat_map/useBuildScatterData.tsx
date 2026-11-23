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

import { useMemo } from 'react';
import { minutesBetweenDates } from '../../../../../utils/Time';
import { ApexIrThreatMapSeries, IrThreatMapMarker, IrThreatMapTypeStyle, markerSize } from './irThreatMapUtils';

interface UseBuildScatterDataArgs {
  markers: IrThreatMapMarker[];
  // Entity types shown on the map (the legend filter).
  entityTypes: string[];
  typeStyles: Record<string, IrThreatMapTypeStyle>;
  // Entities scoring below it are left out (the score band filter).
  scoreMin?: number;
  // Two entities closer than this in time (minutes) and score are drawn as one cluster.
  clusterMinutes?: number;
}

const MIN_DIFF_SCORE = 5;

const useBuildScatterData = ({
  markers,
  entityTypes,
  typeStyles,
  scoreMin = 0,
  clusterMinutes = 1080, // 18h, the 7-day window
}: UseBuildScatterDataArgs) => {
  const series: ApexIrThreatMapSeries = useMemo(() => {
    const groups: IrThreatMapMarker[][] = [];
    markers.forEach((item) => {
      if (!entityTypes.includes(item.type) || item.score < scoreMin) return;
      // A cluster holds one entity type only, so its colour and shape stay meaningful.
      const group = groups.find((g) => g[0].type === item.type
        && Math.abs(minutesBetweenDates(g[0].date, item.date)) < clusterMinutes
        && Math.abs(g[0].score - item.score) < MIN_DIFF_SCORE);
      if (group) group.push(item);
      else groups.push([item]);
    });

    return groups.map((group) => {
      // Highest score first: the tooltip lists the most relevant entities on top.
      const sorted = [...group].sort((a, b) => b.score - a.score);
      const head = group[0];
      return {
        name: head.type,
        data: [{
          x: new Date(head.date).getTime(),
          y: head.score,
          fillColor: typeStyles[head.type]?.color ?? '#888888',
          meta: {
            group: sorted,
            size: group.length,
            type: head.type,
          },
        }],
      };
    });
  }, [markers, entityTypes, typeStyles, scoreMin, clusterMinutes]);

  const markerSizes = useMemo(() => series.map((s) => markerSize(s.data[0].meta.size)), [series]);
  const markerShapes = useMemo(() => series.map((s) => typeStyles[s.data[0].meta.type]?.shape ?? 'circle'), [series, typeStyles]);

  return { series, markerSizes, markerShapes };
};

export default useBuildScatterData;
