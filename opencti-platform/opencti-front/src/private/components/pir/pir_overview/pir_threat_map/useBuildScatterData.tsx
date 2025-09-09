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
import { PirThreatMapFragment$data } from './__generated__/PirThreatMapFragment.graphql';
import { getNodes } from '../../../../../utils/connection';
import { minutesBetweenDates } from '../../../../../utils/Time';
import { itemColor } from '../../../../../utils/Colors';
import { PirThreatMapMarker } from './pirThreatMapUtils';

interface UseBuildScatterDataArgs {
  stixDomainObjects: PirThreatMapFragment$data['stixDomainObjects']
  entityTypes: string[]
}

const useBuildScatterData = ({
  stixDomainObjects,
  entityTypes,
}: UseBuildScatterDataArgs) => {
  const series: ApexAxisChartSeries = useMemo(() => {
    const groupedData: PirThreatMapMarker[][] = [];
    getNodes(stixDomainObjects).forEach((d) => {
      const item = {
        id: d.id,
        date: d.refreshed_at ?? d.updated_at,
        score: d.pirInformation?.pir_score ?? 0,
        name: d?.representative?.main ?? '',
        type: d?.entity_type ?? '',
      };
      if (entityTypes.includes(item.type)) {
        if (Object.keys(groupedData).length === 0) {
          groupedData.push([item]);
        } else {
          let filled = false;
          for (const group of groupedData) {
            const diffDate = Math.abs(minutesBetweenDates(group[0].date, item.date));
            const diffScore = Math.abs(group[0].score - item.score);
            if (diffDate < 1080 && diffScore < 5) { // 1080 = 18h
              group.push(item);
              filled = true;
              break;
            }
          }
          if (!filled) groupedData.push([item]);
        }
      }
    });

    return groupedData.map((group) => {
      const item = group[0];
      const color = group.length > 1 ? '#ffffff' : itemColor(item.type);
      return {
        data: [{
          x: new Date(item.date),
          y: item.score,
          fillColor: color,
          meta: {
            group,
            size: group.length,
          },
        }],
      };
    });
  }, [stixDomainObjects, entityTypes]);

  return series;
};

export default useBuildScatterData;
