// /*
// Copyright (c) 2021-2025 Filigran SAS
//
// This file is part of the OpenCTI Enterprise Edition ("EE") and is
// licensed under the OpenCTI Enterprise Edition License (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// https://github.com/OpenCTI-Platform/opencti/blob/master/LICENSE
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// */
//
// import React, { CSSProperties, useState } from 'react';
// import { useTheme } from '@mui/material/styles';
// import Grid from '@mui/material/Grid2';
// import { graphql, PreloadedQuery, useFragment, usePreloadedQuery } from 'react-relay';
// import { InfoOutlined } from '@mui/icons-material';
// import Tooltip from '@mui/material/Tooltip';
// import WidgetScatter from '../../../../components/dashboard/WidgetScatter';
// import type { Theme } from '../../../../components/Theme';
// import Paper from '../../../../components/Paper';
// import { useFormatter } from '../../../../components/i18n';
// import { PirThreatMapFragment$key } from './__generated__/PirThreatMapFragment.graphql';
// import { getNodes } from '../../../../utils/connection';
// import { itemColor } from '../../../../utils/Colors';
// import { minutesBetweenDates } from '../../../../utils/Time';
// import PirThreatMapLegend from './PirThreatMapLegend';
// import { uniqueArray } from '../../../../utils/utils';
// import { PirThreatMapQuery } from './__generated__/PirThreatMapQuery.graphql';
//
// const pirThreatMapFragment = graphql`
//   fragment PirThreatMapFragment on Query {
//     pirRelationships(
//       first: 100
//       orderBy: pir_score
//       orderMode: desc
//       toId: $pirId
//       filters: $filters
//     ) {
//       edges {
//         node {
//           pir_score
//           updated_at
//           from {
//             ...on StixCoreObject {
//               entity_type
//               representative {
//                 main
//               }
//             }
//           }
//         }
//       }
//     }
//   }
// `;
//
// export const pirThreatMapQuery = graphql`
//   query PirThreatMapQuery($filters: FilterGroup, $pirId: StixRef) {
//     ...PirThreatMapFragment
//   }
// `;
//
// interface PirThreatMapProps {
//   queryRef: PreloadedQuery<PirThreatMapQuery>
// }
//
// const PirThreatMap = ({ queryRef }: PirThreatMapProps) => {
//   const CHART_SIZE = 500;
//   const theme = useTheme<Theme>();
//   const { t_i18n } = useFormatter();
//
//   const query = usePreloadedQuery(pirThreatMapQuery, queryRef);
//   const { stixRefRelationships } = useFragment<PirThreatMapFragment$key>(pirThreatMapFragment, query);
//   const data = getNodes(stixRefRelationships);
//
//   const entityTypes = uniqueArray(data.flatMap((d) => (d.from?.entity_type ? d.from.entity_type : [])));
//   const [filteredEntityTypes, setFilteredEntityTypes] = useState(entityTypes);
//
//   const groupedData: { date: string, score: number, name: string, type: string }[][] = [];
//   data.forEach((d) => {
//     const item = {
//       date: d.updated_at,
//       score: d.pir_score ?? 0,
//       name: d.from?.representative?.main ?? '',
//       type: d.from?.entity_type ?? '',
//     };
//     if (filteredEntityTypes.includes(item.type)) {
//       if (Object.keys(groupedData).length === 0) {
//         groupedData.push([item]);
//       } else {
//         let filled = false;
//         for (const group of groupedData) {
//           const diffDate = Math.abs(minutesBetweenDates(group[0].date, item.date));
//           const diffScore = Math.abs(group[0].score - item.score);
//           if (diffDate < 1440 && diffScore < 5) {
//             group.push(item);
//             filled = true;
//             break;
//           }
//         }
//         if (!filled) groupedData.push([item]);
//       }
//     }
//   });
//
//   const series: ApexAxisChartSeries = groupedData.map((group) => {
//     const item = group[0];
//     const color = group.length > 1 ? '#ffffff' : itemColor(item.type);
//     return {
//       data: [{
//         x: new Date(item.date),
//         y: item.score,
//         fillColor: color,
//         meta: {
//           group,
//           size: group.length,
//         },
//       }],
//     };
//   });
//
//   const containerStyle: CSSProperties = {
//     position: 'relative',
//     paddingLeft: theme.spacing(1),
//     paddingBottom: theme.spacing(1.5),
//     fontSize: 12,
//   };
//
//   const legendStyle: CSSProperties = {
//     position: 'absolute',
//     display: 'flex',
//     justifyContent: 'space-between',
//   };
//
//   const xLegendStyle: CSSProperties = {
//     ...legendStyle,
//     bottom: -6,
//     left: theme.spacing(1),
//     right: 0,
//   };
//
//   const yLegendStyle: CSSProperties = {
//     ...legendStyle,
//     transform: 'rotate(-90deg)',
//     transformOrigin: 'top left',
//     width: CHART_SIZE,
//     left: -12,
//   };
//
//   const title = (
//     <div style={{ display: 'flex', alignItems: 'center', gap: theme.spacing(1) }}>
//       {t_i18n('Threat map')}
//       <Tooltip title={t_i18n('Threat map explanations...')}>
//         <InfoOutlined
//           color='primary'
//           fontSize="small"
//           style={{ paddingBottom: 4, paddingTop: 1 }}
//         />
//       </Tooltip>
//     </div>
//   );
//
//   return (
//     <Grid size={{ xs: 12 }}>
//       <Paper title={title}>
//         <div style={containerStyle}>
//           <div style={{ height: CHART_SIZE }}>
//             <WidgetScatter series={series} />
//           </div>
//           <div style={xLegendStyle}>
//             <span>Less recent</span>
//             <span>Most recent</span>
//           </div>
//           <div style={yLegendStyle}>
//             <span>0 - Less relevant</span>
//             <span>Most relevant - 100</span>
//           </div>
//         </div>
//         <PirThreatMapLegend
//           entityTypes={entityTypes}
//           onFilter={setFilteredEntityTypes}
//         />
//       </Paper>
//     </Grid>
//   );
// };
//
// export default PirThreatMap;
