import React, { memo } from 'react';
import WidgetText from '../../../../components/dashboard/WidgetText';
import type { Widget } from '../../../../utils/widget/widget';

interface DashboardRawVizProps {
  widget: Widget
}

const DashboardRawViz = ({ widget }: DashboardRawVizProps) => {
  switch (widget.type) {
    case 'text':
      return (
        <WidgetText
          parameters={widget.parameters}
          variant="inLine"
        />
      );
    default:
      return 'Not implemented yet';
  }
};

export default memo(DashboardRawViz);
