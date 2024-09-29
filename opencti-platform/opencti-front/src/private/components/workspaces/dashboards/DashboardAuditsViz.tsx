import React, { memo } from 'react';
import AuditsNumber from '@components/common/audits/AuditsNumber';
import AuditsList from '@components/common/audits/AuditsList';
import AuditsDistributionList from '@components/common/audits/AuditsDistributionList';
import AuditsMultiVerticalBars from '@components/common/audits/AuditsMultiVerticalBars';
import AuditsMultiLineChart from '@components/common/audits/AuditsMultiLineChart';
import AuditsMultiAreaChart from '@components/common/audits/AuditsMultiAreaChart';
import AuditsDonut from '@components/common/audits/AuditsDonut';
import AuditsPolarArea from '@components/common/audits/AuditsPolarArea';
import AuditsHorizontalBars from '@components/common/audits/AuditsHorizontalBars';
import AuditsRadar from '@components/common/audits/AuditsRadar';
import AuditsMultiHeatMap from '@components/common/audits/AuditsMultiHeatMap';
import AuditsTreeMap from '@components/common/audits/AuditsTreeMap';
import AuditsWordCloud from '@components/common/audits/AuditsWordCloud';
import MetricsMonthlyChart from '@components/settings/metrics/MetricsMonthlyChart';
import MetricsWeeklyChart from '@components/settings/metrics/MetricsWeeklyChart';
import MetricsMonthly from '@components/settings/metrics/MetricsMonthly';
import MetricsWeekly from '@components/settings/metrics/MetricsWeekly';
import { computerRelativeDate, dayStartDate, formatDate } from '../../../../utils/Time';
import type { Widget } from '../../../../utils/widget/widget';
import { useRemoveIdAndIncorrectKeysFromFilterGroupObject } from '../../../../utils/filters/filtersUtils';

interface DashboardAuditsVizProps {
  widget: Widget
  isReadonly: boolean
  config: {
    relativeDate: string | undefined
    startDate: string
    endDate: string
  }
}

const DashboardAuditsViz = ({
  widget,
  isReadonly,
  config,
}: DashboardAuditsVizProps) => {
  const startDate = config.relativeDate
    ? computerRelativeDate(config.relativeDate)
    : config.startDate;

  const endDate = config.relativeDate
    ? formatDate(dayStartDate(null, false))
    : config.endDate;

  let mainEntityTypes = ['Stix-Core-Object'];
  if (widget?.perspective === 'relationships') {
    mainEntityTypes = ['stix-core-relationship', 'stix-sighting-relationship'];
  } else if (widget?.perspective === 'audits') {
    mainEntityTypes = ['History'];
  }
  const dataSelection = widget?.dataSelection.map((data) => ({
    ...data,
    filters: useRemoveIdAndIncorrectKeysFromFilterGroupObject(data.filters, mainEntityTypes),
    dynamicFrom: useRemoveIdAndIncorrectKeysFromFilterGroupObject(data.dynamicFrom, ['Stix-Core-Object']),
    dynamicTo: useRemoveIdAndIncorrectKeysFromFilterGroupObject(data.dynamicTo, ['Stix-Core-Object']),
  }));

  const isUniqueUser = widget?.parameters?.uniqueUsers === true;
  const isWeekly = widget?.parameters?.intervalUniqueUsers === 'weeks';
  const isMonthly = widget?.parameters?.intervalUniqueUsers === 'months';

  switch (widget?.type) {
    case 'number':
      if (isUniqueUser && isWeekly) {
        return (
          <MetricsWeekly
            variant="inLine"
            endDate={endDate}
            startDate={startDate}
            dataSelection={dataSelection}
            parameters={widget?.parameters as object}
          />
        );
      }
      if (isUniqueUser && isMonthly) {
        return (
          <MetricsMonthly
            variant="inLine"
            endDate={endDate}
            startDate={startDate}
            dataSelection={dataSelection}
            parameters={widget?.parameters as object}
          />
        );
      }
      return (
        <AuditsNumber
          variant="inLine"
          endDate={endDate}
          startDate={startDate}
          dataSelection={dataSelection}
          parameters={widget?.parameters as object} // because calling js component in ts
          height={undefined} // because calling js component in ts
        />
      );
    case 'list':
      return (
        <AuditsList
          variant="inLine"
          endDate={endDate}
          startDate={startDate}
          dataSelection={dataSelection}
          parameters={widget?.parameters as object} // because calling js component in ts
          height={undefined} // because calling js component in ts
        />
      );
    case 'distribution-list':
      return (
        <AuditsDistributionList
          variant="inLine"
          endDate={endDate}
          startDate={startDate}
          dataSelection={dataSelection}
          parameters={widget?.parameters as object} // because calling js component in ts
          height={undefined} // because calling js component in ts
        />
      );
    case 'vertical-bar':
      if (isUniqueUser && isWeekly) {
        return (
          <MetricsWeeklyChart
            variant="inLine"
            endDate={endDate}
            startDate={startDate}
            dataSelection={dataSelection}
            parameters={widget?.parameters as object}
          />
        );
      }
      if (isUniqueUser && isMonthly) {
        return (
          <MetricsMonthlyChart
            variant="inLine"
            endDate={endDate}
            startDate={startDate}
            dataSelection={dataSelection}
            parameters={widget?.parameters as object}
          />
        );
      }
      return (
        <AuditsMultiVerticalBars
          variant="inLine"
          endDate={endDate}
          startDate={startDate}
          isReadOnly={isReadonly}
          withExportPopover={true}
          dataSelection={dataSelection}
          parameters={widget?.parameters as object} // because calling js component in ts
          height={undefined} // because calling js component in ts
        />
      );
    case 'line':
      return (
        <AuditsMultiLineChart
          variant="inLine"
          endDate={endDate}
          startDate={startDate}
          isReadOnly={isReadonly}
          withExportPopover={true}
          dataSelection={dataSelection}
          parameters={widget?.parameters as object} // because calling js component in ts
          height={undefined} // because calling js component in ts
        />
      );
    case 'area':
      return (
        <AuditsMultiAreaChart
          variant="inLine"
          endDate={endDate}
          startDate={startDate}
          isReadOnly={isReadonly}
          withExportPopover={true}
          dataSelection={dataSelection}
          parameters={widget?.parameters as object} // because calling js component in ts
          height={undefined} // because calling js component in ts
        />
      );
    case 'donut':
      return (
        <AuditsDonut
          variant="inLine"
          endDate={endDate}
          startDate={startDate}
          isReadOnly={isReadonly}
          withExportPopover={true}
          dataSelection={dataSelection}
          parameters={widget?.parameters as object} // because calling js component in ts
          height={undefined} // because calling js component in ts
        />
      );
    case 'polar-area':
      return (
        <AuditsPolarArea
          variant="inLine"
          endDate={endDate}
          startDate={startDate}
          isReadOnly={isReadonly}
          withExportPopover={true}
          dataSelection={dataSelection}
          parameters={widget?.parameters as object} // because calling js component in ts
          height={undefined} // because calling js component in ts
        />
      );
    case 'horizontal-bar':
      return (
        <AuditsHorizontalBars
          variant="inLine"
          endDate={endDate}
          startDate={startDate}
          isReadOnly={isReadonly}
          withExportPopover={true}
          dataSelection={dataSelection}
          parameters={widget?.parameters as object} // because calling js component in ts
          height={undefined} // because calling js component in ts
        />
      );
    case 'radar':
      return (
        <AuditsRadar
          variant="inLine"
          endDate={endDate}
          startDate={startDate}
          isReadOnly={isReadonly}
          withExportPopover={true}
          dataSelection={dataSelection}
          parameters={widget?.parameters as object} // because calling js component in ts
          height={undefined} // because calling js component in ts
        />
      );
    case 'heatmap':
      return (
        <AuditsMultiHeatMap
          variant="inLine"
          endDate={endDate}
          startDate={startDate}
          withExportPopover={true}
          dataSelection={dataSelection}
          parameters={widget?.parameters as object} // because calling js component in ts
          height={undefined} // because calling js component in ts
        />
      );
    case 'tree':
      return (
        <AuditsTreeMap
          variant="inLine"
          endDate={endDate}
          startDate={startDate}
          isReadOnly={isReadonly}
          withExportPopover={true}
          dataSelection={dataSelection}
          parameters={widget?.parameters as object} // because calling js component in ts
          height={undefined} // because calling js component in ts
        />
      );
    case 'wordcloud':
      return (
        <AuditsWordCloud
          variant="inLine"
          endDate={endDate}
          startDate={startDate}
          dataSelection={dataSelection}
          parameters={widget?.parameters as object} // because calling js component in ts
          height={undefined} // because calling js component in ts
        />
      );
    default:
      return 'Not implemented yet';
  }
};

export default memo(DashboardAuditsViz);
