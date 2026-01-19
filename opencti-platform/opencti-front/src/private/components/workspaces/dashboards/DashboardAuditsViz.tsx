import React, { memo, ReactNode } from 'react';
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
import { computerRelativeDate, dayStartDate, formatDate } from '../../../../utils/Time';
import type { Widget } from '../../../../utils/widget/widget';
import { useRemoveIdAndIncorrectKeysFromFilterGroupObject } from '../../../../utils/filters/filtersUtils';

interface DashboardAuditsVizProps {
  widget: Widget;
  popover?: ReactNode;
  config: {
    relativeDate: string | undefined;
    startDate: string;
    endDate: string;
  };
}

const DashboardAuditsViz = ({
  widget,
  popover,
  config,
}: DashboardAuditsVizProps) => {
  const startDate = config.relativeDate
    ? computerRelativeDate(config.relativeDate)
    : config.startDate;

  const endDate = config.relativeDate
    ? formatDate(dayStartDate(null, false))
    : config.endDate;

  let mainEntityTypes = ['Stix-Core-Object'];
  if (widget.perspective === 'relationships') {
    mainEntityTypes = ['stix-core-relationship', 'stix-sighting-relationship'];
  } else if (widget.perspective === 'audits') {
    mainEntityTypes = ['History'];
  }
  const dataSelection = widget.dataSelection.map((data) => ({
    ...data,
    filters: useRemoveIdAndIncorrectKeysFromFilterGroupObject(data.filters, mainEntityTypes),
    dynamicFrom: useRemoveIdAndIncorrectKeysFromFilterGroupObject(data.dynamicFrom, ['Stix-Core-Object']),
    dynamicTo: useRemoveIdAndIncorrectKeysFromFilterGroupObject(data.dynamicTo, ['Stix-Core-Object']),
  }));

  switch (widget.type) {
    case 'number':
      return (
        <AuditsNumber
          endDate={endDate}
          startDate={startDate}
          dataSelection={dataSelection}
          entityType={undefined} // because calling js component in ts
          parameters={widget.parameters as object} // because calling js component in ts
        />
      );
    case 'list':
      return (
        <AuditsList
          variant={undefined} // because calling js component in ts
          endDate={endDate}
          startDate={startDate}
          dataSelection={dataSelection}
          parameters={widget.parameters as object} // because calling js component in ts
          height={undefined} // because calling js component in ts
          popover={popover}
        />
      );
    case 'distribution-list':
      return (
        <AuditsDistributionList
          variant={undefined} // because calling js component in ts
          endDate={endDate}
          startDate={startDate}
          dataSelection={dataSelection}
          parameters={widget.parameters as object} // because calling js component in ts
          height={undefined} // because calling js component in ts
          popover={popover}
        />
      );
    case 'vertical-bar':
      return (
        <AuditsMultiVerticalBars
          variant={undefined} // because calling js component in ts
          endDate={endDate}
          startDate={startDate}
          dataSelection={dataSelection}
          parameters={widget.parameters as object} // because calling js component in ts
          height={undefined} // because calling js component in ts
          popover={popover}
        />
      );
    case 'line':
      return (
        <AuditsMultiLineChart
          variant={undefined} // because calling js component in ts
          endDate={endDate}
          startDate={startDate}
          dataSelection={dataSelection}
          parameters={widget.parameters as object} // because calling js component in ts
          height={undefined} // because calling js component in ts
          popover={popover}
        />
      );
    case 'area':
      return (
        <AuditsMultiAreaChart
          variant={undefined} // because calling js component in ts
          endDate={endDate}
          startDate={startDate}
          dataSelection={dataSelection}
          parameters={widget.parameters as object} // because calling js component in ts
          height={undefined} // because calling js component in ts
          popover={popover}
        />
      );
    case 'donut':
      return (
        <AuditsDonut
          variant={undefined} // because calling js component in ts
          endDate={endDate}
          startDate={startDate}
          dataSelection={dataSelection}
          parameters={widget.parameters as object} // because calling js component in ts
          height={undefined} // because calling js component in ts
          popover={popover}
        />
      );
    case 'polar-area':
      return (
        <AuditsPolarArea
          variant={undefined} // because calling js component in ts
          endDate={endDate}
          startDate={startDate}
          dataSelection={dataSelection}
          parameters={widget.parameters as object} // because calling js component in ts
          height={undefined} // because calling js component in ts
          popover={popover}
        />
      );
    case 'horizontal-bar':
      return (
        <AuditsHorizontalBars
          variant={undefined} // because calling js component in ts
          endDate={endDate}
          startDate={startDate}
          dataSelection={dataSelection}
          parameters={widget.parameters as object} // because calling js component in ts
          height={undefined} // because calling js component in ts
          popover={popover}
        />
      );
    case 'radar':
      return (
        <AuditsRadar
          variant={undefined} // because calling js component in ts
          endDate={endDate}
          startDate={startDate}
          dataSelection={dataSelection}
          parameters={widget.parameters as object} // because calling js component in ts
          height={undefined} // because calling js component in ts
          popover={popover}
        />
      );
    case 'heatmap':
      return (
        <AuditsMultiHeatMap
          variant={undefined} // because calling js component in ts
          endDate={endDate}
          startDate={startDate}
          dataSelection={dataSelection}
          parameters={widget.parameters as object} // because calling js component in ts
          height={undefined} // because calling js component in ts
          popover={popover}
        />
      );
    case 'tree':
      return (
        <AuditsTreeMap
          variant={undefined} // because calling js component in ts
          endDate={endDate}
          startDate={startDate}
          dataSelection={dataSelection}
          parameters={widget.parameters as object} // because calling js component in ts
          height={undefined} // because calling js component in ts
          popover={popover}
        />
      );
    case 'wordcloud':
      return (
        <AuditsWordCloud
          variant={undefined} // because calling js component in ts
          endDate={endDate}
          startDate={startDate}
          dataSelection={dataSelection}
          parameters={widget.parameters as object} // because calling js component in ts
          height={undefined} // because calling js component in ts
          popover={popover}
        />
      );
    default:
      return 'Not implemented yet';
  }
};

export default memo(DashboardAuditsViz);
