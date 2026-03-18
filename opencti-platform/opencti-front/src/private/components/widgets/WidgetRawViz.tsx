import { memo, ReactNode } from 'react';
import WidgetText from '../../../components/dashboard/WidgetText';
import type { Widget } from '../../../utils/widget/widget';

interface WidgetRawVizProps {
  widget: Widget;
  popover?: ReactNode;
}

const WidgetRawViz = ({
  widget,
  popover,
}: WidgetRawVizProps) => {
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

export default memo(WidgetRawViz);
