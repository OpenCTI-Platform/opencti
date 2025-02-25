import React, { memo } from 'react';
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

interface DashboardEntitiesVizProps {
  widget: Widget
  isReadonly: boolean
  config: {
    relativeDate: string | undefined
    startDate: string
    endDate: string
  }
}

const DashboardEntitiesViz = ({
  widget,
  isReadonly,
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
          variant="inLine"
          dataSelection={dataSelection}
          parameters={widget.parameters as object} // because calling js component in ts
          height={undefined} // because calling js component in ts
        />
      );
    case 'number':
      return (
        <StixCoreObjectsNumber
          variant="inLine"
          endDate={endDate}
          startDate={startDate}
          dataSelection={dataSelection}
          parameters={widget.parameters as object} // because calling js component in ts
          height={undefined} // because calling js component in ts
          withoutTitle={false} // because calling js component in ts
        />
      );
    case 'list':
      return (
        <StixCoreObjectsList
          variant="inLine"
          endDate={endDate}
          startDate={startDate}
          widgetId={widget.id}
          dataSelection={dataSelection}
          parameters={widget.parameters as object} // because calling js component in ts
          height={undefined} // because calling js component in ts
          title={undefined} // because calling js component in ts
        />
      );
    case 'distribution-list':
      return (
        <StixCoreObjectsDistributionList
          variant="inLine"
          endDate={endDate}
          startDate={startDate}
          dataSelection={dataSelection}
          parameters={widget.parameters as object} // because calling js component in ts
          height={undefined} // because calling js component in ts
        />
      );
    case 'vertical-bar':
      return (
        <StixCoreObjectsMultiVerticalBars
          variant="inLine"
          endDate={endDate}
          startDate={startDate}
          isReadOnly={isReadonly}
          withExportPopover={true}
          dataSelection={dataSelection}
          parameters={widget.parameters as object} // because calling js component in ts
          height={undefined} // because calling js component in ts
        />
      );
    case 'line':
      return (
        <StixCoreObjectsMultiLineChart
          variant="inLine"
          endDate={endDate}
          startDate={startDate}
          isReadOnly={isReadonly}
          withExportPopover={true}
          dataSelection={dataSelection}
          parameters={widget.parameters as object} // because calling js component in ts
          height={undefined} // because calling js component in ts
        />
      );
    case 'area':
      return (
        <StixCoreObjectsMultiAreaChart
          variant="inLine"
          endDate={endDate}
          startDate={startDate}
          isReadOnly={isReadonly}
          withExportPopover={true}
          dataSelection={dataSelection}
          parameters={widget.parameters as object} // because calling js component in ts
          height={undefined} // because calling js component in ts
        />
      );
    case 'timeline':
      return (
        <StixCoreObjectsTimeline
          variant="inLine"
          endDate={endDate}
          startDate={startDate}
          dataSelection={dataSelection}
          parameters={widget.parameters as object} // because calling js component in ts
          height={undefined} // because calling js component in ts
        />
      );
    case 'donut':
      return (
        <StixCoreObjectsDonut
          variant="inLine"
          endDate={endDate}
          startDate={startDate}
          isReadOnly={isReadonly}
          withExportPopover={true}
          dataSelection={dataSelection}
          parameters={widget.parameters as object} // because calling js component in ts
        />
      );
    case 'polar-area':
      return (
        <StixCoreObjectsPolarArea
          variant="inLine"
          endDate={endDate}
          startDate={startDate}
          isReadOnly={isReadonly}
          withExportPopover={true}
          dataSelection={dataSelection}
          parameters={widget.parameters}
        />
      );
    case 'horizontal-bar':
      if (
        dataSelection.length > 1
        && dataSelection[0].attribute?.endsWith('_id')
      ) {
        return (
          <StixCoreObjectsMultiHorizontalBars
            variant="inLine"
            endDate={endDate}
            startDate={startDate}
            isReadOnly={isReadonly}
            withExportPopover={true}
            dataSelection={dataSelection}
            parameters={widget.parameters as object} // because calling js component in ts
            height={undefined} // because calling js component in ts
          />
        );
      }
      return (
        <StixCoreObjectsHorizontalBars
          variant="inLine"
          endDate={endDate}
          startDate={startDate}
          isReadOnly={isReadonly}
          withExportPopover={true}
          dataSelection={dataSelection}
          parameters={widget.parameters as object} // because calling js component in ts
          height={undefined} // because calling js component in ts
        />
      );
    case 'radar':
      return (
        <StixCoreObjectsRadar
          variant="inLine"
          endDate={endDate}
          startDate={startDate}
          isReadOnly={isReadonly}
          withExportPopover={true}
          dataSelection={dataSelection}
          parameters={widget.parameters as object} // because calling js component in ts
          height={undefined} // because calling js component in ts
        />
      );
    case 'heatmap':
      return (
        <StixCoreObjectsMultiHeatMap
          variant="inLine"
          endDate={endDate}
          startDate={startDate}
          isReadOnly={isReadonly}
          withExportPopover={true}
          dataSelection={dataSelection}
          parameters={widget.parameters as object} // because calling js component in ts
          height={undefined} // because calling js component in ts
        />
      );
    case 'tree':
      return (
        <StixCoreObjectsTreeMap
          variant="inLine"
          endDate={endDate}
          startDate={startDate}
          isReadOnly={isReadonly}
          withExportPopover={true}
          dataSelection={dataSelection}
          parameters={widget.parameters as object} // because calling js component in ts
          height={undefined} // because calling js component in ts
        />
      );
    case 'wordcloud':
      return (
        <StixCoreObjectsWordCloud
          variant="inLine"
          endDate={endDate}
          startDate={startDate}
          dataSelection={dataSelection}
          parameters={widget.parameters as object} // because calling js component in ts
        />
      );
    default:
      return 'Not implemented yet';
  }
};

export default memo(DashboardEntitiesViz);
