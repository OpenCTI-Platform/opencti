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

import React, { FunctionComponent, ReactNode, useCallback, useEffect, useState } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { AuditsNumberNumberSeriesQuery } from '@components/common/audits/__generated__/AuditsNumberNumberSeriesQuery.graphql';
import { useFormatter } from '../../../../components/i18n';
import { dayAgo } from '../../../../utils/Time';
import WidgetContainer from '../../../../components/dashboard/WidgetContainer';
import WidgetNoData from '../../../../components/dashboard/WidgetNoData';
import WidgetNumber from '../../../../components/dashboard/WidgetNumber';
import useDashboardViz from '../../../../components/dashboard/useDashboardViz';
import { UNIQUE_COUNT_ESTIMATION_THRESHOLD, UNIQUE_COUNT_ESTIMATION_WARNING, useGetNumberWidgetTitle } from '../../../../utils/widget/widgetUtils';
import type { WidgetDataSelection, WidgetHost, WidgetParameters } from '../../../../utils/widget/widget';
import type { DashboardConfig } from '../../../../components/dashboard/dashboard-types';
import { buildFiltersAndOptionsForWidgets, normalizeFilterGroupForBackend } from '../../../../utils/filters/filtersUtils';
import AuditsWidgetRenderContent from '../../../../components/dashboard/AuditsWidgetRenderContent';

const auditsNumberNumberQuery = graphql`
  query AuditsNumberNumberSeriesQuery(
    $types: [String]
    $startDate: DateTime
    $endDate: DateTime
    $onlyInferred: Boolean
    $filters: FilterGroup
    $search: String
    $field: String
    $unique: Boolean
  ) {
    auditsNumber(
      types: $types
      startDate: $startDate
      endDate: $endDate
      onlyInferred: $onlyInferred
      filters: $filters
      search: $search
      field: $field
      unique: $unique
    ) {
      total
      count
    }
  }
`;

interface AuditsNumberComponentProps {
  queryRef: PreloadedQuery<AuditsNumberNumberSeriesQuery>;
  entityType?: string;
  label: string;
  isUnique: boolean;
  onShowWarning: (show: boolean) => void;
}

const AuditsNumberComponent: FunctionComponent<AuditsNumberComponentProps> = ({
  queryRef,
  entityType,
  label,
  isUnique,
  onShowWarning,
}) => {
  const { t_i18n } = useFormatter();
  const data = usePreloadedQuery<AuditsNumberNumberSeriesQuery>(
    auditsNumberNumberQuery,
    queryRef,
  );

  useEffect(() => {
    onShowWarning(isUnique && (data.auditsNumber?.total ?? 0) > UNIQUE_COUNT_ESTIMATION_THRESHOLD);
  }, [isUnique, data.auditsNumber?.total, onShowWarning]);

  if (data.auditsNumber) {
    const { total, count } = data.auditsNumber;
    return (
      <WidgetNumber
        entityType={entityType}
        label={label}
        value={total}
        diffLabel={t_i18n('24 hours')}
        diffValue={total - count}
      />
    );
  }

  return <WidgetNoData />;
};

interface AuditsNumberProps {
  startDate?: string | null;
  endDate?: string | null;
  dataSelection: WidgetDataSelection[];
  parameters?: WidgetParameters;
  config: DashboardConfig;
  refreshRate?: number | null;
  entityType?: string;
  popover?: ReactNode;
  variant?: string;
  height?: number;
  host?: WidgetHost;
}

const AuditsNumber: FunctionComponent<AuditsNumberProps> = ({
  startDate,
  endDate,
  dataSelection,
  parameters = {},
  config,
  refreshRate = null,
  entityType,
  popover,
  variant,
  height,
  host,
}) => {
  const [showWarning, setShowWarning] = useState(false);
  const { t_i18n } = useFormatter();

  const buildQueryVariables = useCallback((resolvedDataSelection: WidgetDataSelection[]): AuditsNumberNumberSeriesQuery['variables'] => {
    const selection = resolvedDataSelection[0];
    const types = ['History', 'Activity'];
    const dateAttribute = selection.date_attribute && selection.date_attribute.length > 0
      ? selection.date_attribute
      : 'timestamp';
    const { filters } = buildFiltersAndOptionsForWidgets(
      selection.filters,
      { removeTypeAll: true, startDate: startDate ?? undefined, endDate: endDate ?? undefined, dateAttribute },
    );
    return {
      types,
      filters: normalizeFilterGroupForBackend(filters),
      startDate: startDate ?? undefined,
      endDate: dayAgo(),
      field: selection.attribute,
      unique: selection.unique,
    };
  }, [startDate, endDate]);

  const { resolvedDataSelection, isMissingHostEntity, isMissingSavedFilters, isPreviewMode, queryRef } = useDashboardViz<AuditsNumberNumberSeriesQuery>({
    perspective: 'audits',
    dataSelection,
    host,
    refreshRate,
    query: auditsNumberNumberQuery,
    config,
    parameters,
    buildQueryVariables,
  });
  const DEFAULT_TITLE = t_i18n('Audits number');
  const translatedNumberLabel = useGetNumberWidgetTitle(parameters, DEFAULT_TITLE);

  const selection = resolvedDataSelection[0];
  const warning = showWarning ? t_i18n(UNIQUE_COUNT_ESTIMATION_WARNING) : undefined;

  return (
    <WidgetContainer
      padding="medium"
      height={height}
      title={DEFAULT_TITLE}
      variant={variant}
      action={popover}
      showPreviewTag={isPreviewMode}
      warning={warning}
    >
      <AuditsWidgetRenderContent
        isMissingHostEntity={isMissingHostEntity}
        isMissingSavedFilters={isMissingSavedFilters}
        queryRef={queryRef}
        host={host}
      >
        <AuditsNumberComponent
          queryRef={queryRef!}
          entityType={entityType}
          label={translatedNumberLabel}
          isUnique={Boolean(selection.unique)}
          onShowWarning={setShowWarning}
        />
      </AuditsWidgetRenderContent>
    </WidgetContainer>
  );
};

export default AuditsNumber;
