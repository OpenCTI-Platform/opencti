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

import React from 'react';
import { graphql } from 'react-relay';
import { AuditsTimeSeriesBreakdownQuery } from '@components/common/audits/__generated__/AuditsTimeSeriesBreakdownQuery.graphql';
import { useFormatter } from '../../../../components/i18n';
import TimeSeriesBreakdownViz, { buildTimeSeriesBreakdownSettings, type TimeSeriesBreakdownVizProps } from '../../../../components/dashboard/TimeSeriesBreakdownViz';
import AuditsWidgetRenderContent from '../../../../components/dashboard/AuditsWidgetRenderContent';
import type { WidgetDataSelection, WidgetParameters } from '../../../../utils/widget/widget';
import type { DashboardConfig } from '../../../../components/dashboard/dashboard-types';
import { normalizeFilterGroupForBackend, removeEntityTypeAllFromFilterGroup } from '../../../../utils/filters/filtersUtils';

const auditsTimeSeriesBreakdownQuery = graphql`
  query AuditsTimeSeriesBreakdownQuery(
    $field: String!
    $dateAttribute: String
    $startDate: DateTime!
    $endDate: DateTime
    $interval: String!
    $limit: Int
    $order: OrderingMode
    $includeOther: Boolean
    $types: [String]
    $filters: FilterGroup
  ) {
    auditsTimeSeriesBreakdown(
      field: $field
      dateAttribute: $dateAttribute
      startDate: $startDate
      endDate: $endDate
      interval: $interval
      limit: $limit
      order: $order
      includeOther: $includeOther
      types: $types
      filters: $filters
    ) {
      truncated
      dates
      series {
        label
        isOther
        entity {
          ... on BasicObject {
            id
            entity_type
          }
          ... on StixObject {
            representative {
              main
            }
          }
          # objects without representative
          ... on Creator {
            id
            name
          }
          ... on Group {
            name
          }
        }
        values
      }
    }
  }
`;

// Same logs as the other audits time series: the API narrows them to the ones the user can see
const AUDITS_TYPES = ['History', 'Activity'];

const buildQueryVariables = (
  resolvedDataSelection: WidgetDataSelection[],
  config: DashboardConfig,
  parameters?: WidgetParameters,
): AuditsTimeSeriesBreakdownQuery['variables'] => {
  const [selection] = resolvedDataSelection;
  return {
    ...buildTimeSeriesBreakdownSettings(config, parameters),
    dateAttribute: selection?.date_attribute?.length ? selection.date_attribute : 'timestamp',
    types: AUDITS_TYPES,
    // The period is sent apart from the filters, as the other audits time series do
    filters: normalizeFilterGroupForBackend(removeEntityTypeAllFromFilterGroup(selection?.filters)),
  };
};

const selectBreakdown = (data: AuditsTimeSeriesBreakdownQuery['response']) => data.auditsTimeSeriesBreakdown;

/**
 * Activity time series widget drawing one series per value of `parameters.breakdownBy`, with the
 * guards of the other audits widgets (capabilities and enterprise edition).
 */
const AuditsTimeSeriesBreakdown = (props: TimeSeriesBreakdownVizProps) => {
  const { t_i18n } = useFormatter();
  return (
    <TimeSeriesBreakdownViz<AuditsTimeSeriesBreakdownQuery>
      {...props}
      query={auditsTimeSeriesBreakdownQuery}
      buildQueryVariables={buildQueryVariables}
      selectBreakdown={selectBreakdown}
      defaultTitle={t_i18n('Activity and history')}
      RenderContent={AuditsWidgetRenderContent}
    />
  );
};

export default AuditsTimeSeriesBreakdown;
