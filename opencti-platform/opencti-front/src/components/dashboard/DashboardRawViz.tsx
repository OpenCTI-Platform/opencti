import { memo, ReactNode } from 'react';
import WidgetText from './WidgetText';
import type { Widget, WidgetHost } from 'src/utils/widget/widget';
import StixCoreObjectsCustomAttributes from '@components/common/stix_core_objects/StixCoreObjectsCustomAttributes';
import type { DashboardConfig } from './dashboard-types';
import { computeStartEndDates } from 'src/components/dashboard/dashboardVizUtils';
import WidgetNotImplemented from './WidgetNotImplemented';

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
