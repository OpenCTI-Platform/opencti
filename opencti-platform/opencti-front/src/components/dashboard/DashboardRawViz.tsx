import { memo, ReactNode } from 'react';
import WidgetText from './WidgetText';
import type { Widget, WidgetHost } from '../../utils/widget/widget';
import StixCoreObjectsCustomAttributes from '@components/widgets/StixCoreObjectsCustomAttributes';
import type { DashboardConfig } from './dashboard-types';
import { computeRelativeDate, dayStartDate, formatDate } from '../../utils/Time';
import useHelper from '../../utils/hooks/useHelper';

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
  const { isCustomAttributesWidgetEnable } = useHelper();

  const startDate = config?.relativeDate
    ? computeRelativeDate(config.relativeDate)
    : config?.startDate;

  const endDate = config?.relativeDate
    ? formatDate(dayStartDate(null, false))
    : config?.endDate;

  switch (widget.type) {
    case 'text':
      return (
        <WidgetText
          parameters={widget.parameters}
          popover={popover}
        />
      );
    case 'custom-attributes':
      if (isCustomAttributesWidgetEnable()) {
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
      }
      return;
    default:
      return 'Not implemented yet';
  }
};

export default memo(DashboardRawViz);
