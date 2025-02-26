import React, { memo } from 'react';
import StixRelationshipsNumber from '@components/common/stix_relationships/StixRelationshipsNumber';
import StixRelationshipsList from '@components/common/stix_relationships/StixRelationshipsList';
import StixRelationshipsDistributionList from '@components/common/stix_relationships/StixRelationshipsDistributionList';
import StixRelationshipsMultiVerticalBars from '@components/common/stix_relationships/StixRelationshipsMultiVerticalBars';
import StixRelationshipsMultiLineChart from '@components/common/stix_relationships/StixRelationshipsMultiLineChart';
import StixRelationshipsMultiAreaChart from '@components/common/stix_relationships/StixRelationshipsMultiAreaChart';
import StixRelationshipsTimeline from '@components/common/stix_relationships/StixRelationshipsTimeline';
import StixRelationshipsDonut from '@components/common/stix_relationships/StixRelationshipsDonut';
import StixRelationshipsMultiHorizontalBars from '@components/common/stix_relationships/StixRelationshipsMultiHorizontalBars';
import StixRelationshipsHorizontalBars from '@components/common/stix_relationships/StixRelationshipsHorizontalBars';
import StixRelationshipsRadar from '@components/common/stix_relationships/StixRelationshipsRadar';
import StixRelationshipsPolarArea from '@components/common/stix_relationships/StixRelationshipsPolarArea';
import StixRelationshipsMultiHeatMap from '@components/common/stix_relationships/StixRelationshipsMultiHeatMap';
import StixRelationshipsTreeMap from '@components/common/stix_relationships/StixRelationshipsTreeMap';
import StixRelationshipsMap from '@components/common/stix_relationships/StixRelationshipsMap';
import StixRelationshipsWordCloud from '@components/common/stix_relationships/StixRelationshipsWordCloud';
import { computerRelativeDate, dayStartDate, formatDate } from '../../../../utils/Time';
import type { Widget } from '../../../../utils/widget/widget';
import { useRemoveIdAndIncorrectKeysFromFilterGroupObject } from '../../../../utils/filters/filtersUtils';

interface DashboardRelationshipsVizProps {
  widget: Widget
  isReadonly: boolean
  config: {
    relativeDate: string | undefined
    startDate: string
    endDate: string
  }
}

const DashboardRelationshipsViz = ({
  widget,
  isReadonly,
  config,
}: DashboardRelationshipsVizProps) => {
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
        <StixRelationshipsNumber
          variant="inLine"
          endDate={endDate}
          startDate={startDate}
          dataSelection={dataSelection}
          parameters={widget.parameters as object} // because calling js component in ts
          height={undefined} // because calling js component in ts
        />
      );
    case 'list':
      return (
        <StixRelationshipsList
          variant="inLine"
          endDate={endDate}
          startDate={startDate}
          widgetId={widget.id}
          dataSelection={dataSelection} // dynamicFrom and dynamicTo TODO
          parameters={widget.parameters as object} // because calling js component in ts
          height={undefined} // because calling js component in ts
        />
      );
    case 'distribution-list':
      return (
        <StixRelationshipsDistributionList // TODO idem
          variant="inLine"
          endDate={endDate}
          startDate={startDate}
          dataSelection={dataSelection}
          parameters={widget.parameters as object} // because calling js component in ts
          height={undefined} // because calling js component in ts
          title={undefined} // because calling js component in ts
          field={undefined} // because calling js component in ts
          overflow={undefined} // because calling js component in ts
        />
      );
    case 'vertical-bar':
      return (
        <StixRelationshipsMultiVerticalBars
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
        <StixRelationshipsMultiLineChart
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
        <StixRelationshipsMultiAreaChart
          variant="inLine"
          endDate={endDate}
          startDate={startDate}
          isReadOnly={isReadonly}
          withExportPopover={true}
          dataSelection={dataSelection}
          parameters={widget.parameters as object} // because calling js component in ts
          height={undefined} // because calling js component in ts
          title={undefined} // because calling js component in ts
        />
      );
    case 'timeline':
      return (
        <StixRelationshipsTimeline
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
        <StixRelationshipsDonut
          variant="inLine"
          endDate={endDate}
          startDate={startDate}
          isReadOnly={isReadonly}
          withExportPopover={true}
          dataSelection={dataSelection}
          parameters={widget.parameters as object} // because calling js component in ts
          height={undefined} // because calling js component in ts
          title={undefined} // because calling js component in ts
          field={undefined} // because calling js component in ts
        />
      );
    case 'horizontal-bar':
      if (
        dataSelection.length > 1
        && dataSelection[0].attribute === 'internal_id'
      ) {
        return (
          <StixRelationshipsMultiHorizontalBars
            variant="inLine"
            endDate={endDate}
            startDate={startDate}
            isReadOnly={isReadonly}
            withExportPopover={true}
            dataSelection={dataSelection}
            parameters={widget.parameters as object} // because calling js component in ts
            height={undefined} // because calling js component in ts
            title={undefined} // because calling js component in ts
            field={undefined} // because calling js component in ts
          />
        );
      }
      return (
        <StixRelationshipsHorizontalBars
          variant="inLine"
          endDate={endDate}
          startDate={startDate}
          isReadOnly={isReadonly}
          withExportPopover={true}
          dataSelection={dataSelection}
          parameters={widget.parameters as object} // because calling js component in ts
          height={undefined} // because calling js component in ts
          title={undefined} // because calling js component in ts
          field={undefined} // because calling js component in ts
          withoutTitle={false} // because calling js component in ts
          fromId={false} // because calling js component in ts
          relationshipType={false} // because calling js component in ts
        />
      );
    case 'radar':
      return (
        <StixRelationshipsRadar
          variant="inLine"
          endDate={endDate}
          startDate={startDate}
          isReadOnly={isReadonly}
          withExportPopover={true}
          dataSelection={dataSelection}
          parameters={widget.parameters as object} // because calling js component in ts
          height={undefined} // because calling js component in ts
          title={undefined} // because calling js component in ts
          field={undefined} // because calling js component in ts
        />
      );
    case 'polar-area':
      return (
        <StixRelationshipsPolarArea
          variant="inLine"
          endDate={endDate}
          startDate={startDate}
          isReadOnly={isReadonly}
          withExportPopover={true}
          dataSelection={dataSelection}
          parameters={widget.parameters as object} // because calling js component in ts
          height={undefined} // because calling js component in ts
          title={undefined} // because calling js component in ts
          field={undefined} // because calling js component in ts
        />
      );
    case 'heatmap':
      return (
        <StixRelationshipsMultiHeatMap
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
        <StixRelationshipsTreeMap
          variant="inLine"
          endDate={endDate}
          startDate={startDate}
          isReadOnly={isReadonly}
          withExportPopover={true}
          dataSelection={dataSelection}
          parameters={widget.parameters as object} // because calling js component in ts
          height={undefined} // because calling js component in ts
          title={undefined} // because calling js component in ts
          field={undefined} // because calling js component in ts
        />
      );
    case 'map':
      return (
        <StixRelationshipsMap
          variant="inLine"
          endDate={endDate}
          startDate={startDate}
          dataSelection={dataSelection}
          parameters={widget.parameters as object} // because calling js component in ts
          height={undefined} // because calling js component in ts
          title={undefined} // because calling js component in ts
          field={undefined} // because calling js component in ts
        />
      );
    case 'wordcloud':
      return (
        <StixRelationshipsWordCloud
          variant="inLine"
          endDate={endDate}
          startDate={startDate}
          dataSelection={dataSelection}
          parameters={widget.parameters as object} // because calling js component in ts
          height={undefined} // because calling js component in ts
          title={undefined} // because calling js component in ts
          field={undefined} // because calling js component in ts
        />
      );
    default:
      return 'Not implemented yet';
  }
};

export default memo(DashboardRelationshipsViz);
