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

import React, { FunctionComponent, ReactNode, Suspense, useState, useEffect, useCallback } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { AuditsNumberNumberSeriesQuery, FilterGroup as GqlFilterGroup } from '@components/common/audits/__generated__/AuditsNumberNumberSeriesQuery.graphql';
import { useFormatter } from '../../../../components/i18n';
import { dayAgo } from '../../../../utils/Time';
import useGranted, { SETTINGS_SECURITYACTIVITY, SETTINGS_SETACCESSES, VIRTUAL_ORGANIZATION_ADMIN } from '../../../../utils/hooks/useGranted';
import useEnterpriseEdition from '../../../../utils/hooks/useEnterpriseEdition';
import { buildFiltersAndOptionsForWidgets } from '../../../../utils/filters/filtersUtils';
import WidgetContainer from '../../../../components/dashboard/WidgetContainer';
import WidgetNoData from '../../../../components/dashboard/WidgetNoData';
import WidgetAccessDenied from '../../../../components/dashboard/WidgetAccessDenied';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import useEntityTranslation from '../../../../utils/hooks/useEntityTranslation';
import WidgetNumber from '../../../../components/dashboard/WidgetNumber';
import useDashboardViz from '../../../../components/dashboard/useDashboardViz';
import WidgetNoHostEntity from '../../../../components/dashboard/WidgetNoHostEntity';
import { UNIQUE_COUNT_ESTIMATION_THRESHOLD, UNIQUE_COUNT_ESTIMATION_WARNING } from '../../../../utils/widget/widgetUtils';
import type { WidgetDataSelection, WidgetHost, WidgetParameters } from '../../../../utils/widget/widget';
import type { DashboardConfig } from '../../../../components/dashboard/dashboard-types';

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
  const { translateEntityType } = useEntityTranslation();
  const isGrantedToSettings = useGranted([SETTINGS_SETACCESSES, SETTINGS_SECURITYACTIVITY, VIRTUAL_ORGANIZATION_ADMIN]);
  const isEnterpriseEdition = useEnterpriseEdition();

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
      filters: filters as unknown as GqlFilterGroup,
      startDate: startDate ?? undefined,
      endDate: dayAgo(),
      field: selection.attribute,
      unique: selection.unique,
    };
  }, [startDate, endDate]);

  const { resolvedDataSelection, isMissingHostEntity, isPreviewMode, queryRef } = useDashboardViz<AuditsNumberNumberSeriesQuery>({
    perspective: 'audits',
    dataSelection,
    host,
    refreshRate,
    query: auditsNumberNumberQuery,
    config,
    parameters,
    buildQueryVariables,
  });

  const title = parameters.title ?? t_i18n('Audits number');
  const translatedTitle = translateEntityType(title);

  if (!isGrantedToSettings || !isEnterpriseEdition) {
    return <WidgetAccessDenied />;
  }

  const selection = resolvedDataSelection[0];
  const warning = showWarning ? t_i18n(UNIQUE_COUNT_ESTIMATION_WARNING) : undefined;

  return (
    <WidgetContainer
      padding="medium"
      height={height}
      title={t_i18n('Entities number')}
      variant={variant}
      action={popover}
      showPreviewTag={isPreviewMode}
      warning={warning}
    >
      {isMissingHostEntity ? (
        <WidgetNoHostEntity host={host} />
      ) : queryRef ? (
        <Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
          <AuditsNumberComponent
            queryRef={queryRef}
            entityType={entityType}
            label={translatedTitle}
            isUnique={Boolean(selection.unique)}
            onShowWarning={setShowWarning}
          />
        </Suspense>
      ) : (
        <Loader variant={LoaderVariant.inElement} />
      )}
    </WidgetContainer>
  );
};

export default AuditsNumber;
