import React, { memo, ReactNode } from 'react';
import WidgetText from '../../../../components/dashboard/WidgetText';
import type { Widget } from '../../../../utils/widget/widget';

interface DashboardRawVizProps {
  widget: Widget;
  popover?: ReactNode;
}

const DashboardRawViz = ({
  widget,
  popover,
}: DashboardRawVizProps) => {
  switch (widget.type) {
    case 'text':
      return (
        <WidgetText
          parameters={widget.parameters}
          popover={popover}
        />
      );
    default:
      return 'Not implemented yet';
  }
};

export default memo(DashboardRawViz);
