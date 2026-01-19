import React, { memo, ReactNode } from 'react';
import StixDomainObjectBookmarksList from '@components/common/stix_domain_objects/StixDomainObjectBookmarksList';
import StixCoreObjectsNumber from '@components/common/stix_core_objects/StixCoreObjectsNumber';
import StixCoreObjectsList from '@components/common/stix_core_objects/StixCoreObjectsList';
import StixCoreObjectsDistributionList from '@components/common/stix_core_objects/StixCoreObjectsDistributionList';
import StixCoreObjectsMultiVerticalBars from '@components/common/stix_core_objects/StixCoreObjectsMultiVerticalBars';
import StixCoreObjectsMultiLineChart from '@components/common/stix_core_objects/StixCoreObjectsMultiLineChart';
import StixCoreObjectsMultiAreaChart from '@components/common/stix_core_objects/StixCoreObjectsMultiAreaChart';
import StixCoreObjectsTimeline from '@components/common/stix_core_objects/StixCoreObjectsTimeline';
import StixCoreObjectsDonut from '@components/common/stix_core_objects/StixCoreObjectsDonut';
import StixCoreObjectsPolarArea from '@components/common/stix_core_objects/StixCoreObjectsPolarArea';
import StixCoreObjectsMultiHorizontalBars from '@components/common/stix_core_objects/StixCoreObjectsMultiHorizontalBars';
import StixCoreObjectsHorizontalBars from '@components/common/stix_core_objects/StixCoreObjectsHorizontalBars';
import StixCoreObjectsRadar from '@components/common/stix_core_objects/StixCoreObjectsRadar';
import StixCoreObjectsMultiHeatMap from '@components/common/stix_core_objects/StixCoreObjectsMultiHeatMap';
import StixCoreObjectsTreeMap from '@components/common/stix_core_objects/StixCoreObjectsTreeMap';
import StixCoreObjectsWordCloud from '@components/common/stix_core_objects/StixCoreObjectsWordCloud';
import type { Widget } from '../../../../utils/widget/widget';
import { computerRelativeDate, dayStartDate, formatDate } from '../../../../utils/Time';
import { useRemoveIdAndIncorrectKeysFromFilterGroupObject } from '../../../../utils/filters/filtersUtils';
import { Box } from '@mui/material';

interface DashboardEntitiesVizProps {
  widget: Widget;
  popover?: ReactNode;
  config: {
    relativeDate: string | undefined;
    startDate: string;
    endDate: string;
  };
}

const DashboardEntitiesViz = ({
  widget,
  popover,
  config,
}: DashboardEntitiesVizProps) => {
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
    case 'bookmark':
      return (
        <StixDomainObjectBookmarksList
          variant={undefined} // because calling js component in ts
          dataSelection={dataSelection}
          parameters={widget.parameters as object} // because calling js component in ts
          height={undefined} // because calling js component in ts
          popover={popover}
        />
      );
    case 'number':
      return (
        <StixCoreObjectsNumber
          endDate={endDate}
          startDate={startDate}
          dataSelection={dataSelection}
          entityType={undefined} // because calling js component in ts
          parameters={widget.parameters as object} // because calling js component in ts
          popover={<Box mr={-2}>{popover}</Box>}
        />
      );
    case 'list':
      return (
        <StixCoreObjectsList
          variant={undefined} // because calling js component in ts
          endDate={endDate}
          startDate={startDate}
          widgetId={widget.id}
          dataSelection={dataSelection}
          parameters={widget.parameters as object} // because calling js component in ts
          height={undefined} // because calling js component in ts
          title={undefined} // because calling js component in ts
          popover={popover}
        />
      );
    case 'distribution-list':
      return (
        <StixCoreObjectsDistributionList
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
        <StixCoreObjectsMultiVerticalBars
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
        <StixCoreObjectsMultiLineChart
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
        <StixCoreObjectsMultiAreaChart
          variant={undefined} // because calling js component in ts
          endDate={endDate}
          startDate={startDate}
          dataSelection={dataSelection}
          parameters={widget.parameters as object} // because calling js component in ts
          height={undefined} // because calling js component in ts
          popover={popover}
        />
      );
    case 'timeline':
      return (
        <StixCoreObjectsTimeline
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
        <StixCoreObjectsDonut
          variant={undefined} // because calling js component in ts
          endDate={endDate}
          startDate={startDate}
          dataSelection={dataSelection}
          parameters={widget.parameters as object} // because calling js component in ts
          height={undefined}
          popover={popover}
        />
      );
    case 'polar-area':
      return (
        <StixCoreObjectsPolarArea
          variant={undefined} // because calling js component in ts
          endDate={endDate}
          startDate={startDate}
          dataSelection={dataSelection}
          parameters={widget.parameters}
          popover={popover}
        />
      );
    case 'horizontal-bar':
      if (
        dataSelection.length > 1
        && dataSelection[0].attribute?.endsWith('_id')
      ) {
        return (
          <StixCoreObjectsMultiHorizontalBars
            variant={undefined} // because calling js component in ts
            endDate={endDate}
            startDate={startDate}
            dataSelection={dataSelection}
            parameters={widget.parameters as object} // because calling js component in ts
            height={undefined} // because calling js component in ts
            popover={popover}
          />
        );
      }
      return (
        <StixCoreObjectsHorizontalBars
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
        <StixCoreObjectsRadar
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
        <StixCoreObjectsMultiHeatMap
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
        <StixCoreObjectsTreeMap
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
        <StixCoreObjectsWordCloud
          variant={undefined} // because calling js component in ts
          endDate={endDate}
          startDate={startDate}
          dataSelection={dataSelection}
          parameters={widget.parameters as object} // because calling js component in ts
          height={undefined}
          popover={popover}
        />
      );
    default:
      return 'Not implemented yet';
  }
};

export default memo(DashboardEntitiesViz);
