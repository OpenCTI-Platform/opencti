import { memo, ReactNode } from 'react';
import WidgetText from './WidgetText';
import type { Widget, WidgetHost } from 'src/utils/widget/widget';
import StixCoreObjectsCustomAttributes from '@components/common/stix_core_objects/StixCoreObjectsCustomAttributes';
import type { DashboardConfig } from './dashboard-types';
import { computeStartEndDates } from 'src/components/dashboard/dashboardVizUtils';
import WidgetNotImplemented from './WidgetNotImplemented';
import ContainerTimelineWidget from '../../private/components/common/timeline/ContainerTimelineWidget';

interface DashboardRawVizProps {
  widget: Widget;
  popover?: ReactNode;
  config?: DashboardConfig;
  host?: WidgetHost;
}

const DashboardRawViz = ({
  widget,
  popover,
  config,
  host,
}: DashboardRawVizProps) => {
  const { startDate, endDate } = computeStartEndDates(config);

  switch (widget.type) {
    case 'text':
      return (
        <WidgetText
          parameters={widget.parameters}
          popover={popover}
        />
      );
    case 'case-timeline':
      return (
        <ContainerTimelineWidget
          parameters={{
            ...widget.parameters,
            // In a custom view, the widget always shows the timeline of the incident or case it is displayed on
            container_id: host?.kind === 'custom-view' ? host.customViewTargetEntityId : widget.parameters?.container_id,
          }}
          popover={popover}
        />
      );
    case 'custom-attributes':
      return (
        <StixCoreObjectsCustomAttributes
          variant={undefined}
          height={undefined}
          endDate={endDate ?? undefined}
          startDate={startDate ?? undefined}
          widgetId={widget.id}
          dataSelection={widget.dataSelection}
          parameters={widget.parameters as Record<string, unknown>}
          title={undefined}
          popover={popover}
          host={host}
        />
      );
    default:
      return (
        <WidgetNotImplemented popover={popover} />
      );
  }
};

export default memo(DashboardRawViz);
