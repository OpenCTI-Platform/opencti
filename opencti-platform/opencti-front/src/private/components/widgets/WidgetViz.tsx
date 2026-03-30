import { ReactNode } from 'react';
import { ErrorBoundary } from '../Error';
import WidgetRawViz from '../widgets/WidgetRawViz';
import WidgetRelationshipsViz from '../widgets/WidgetRelationshipsViz';
import WidgetAuditsViz from '../widgets/WidgetAuditsViz';
import WidgetEntitiesViz from '../widgets/WidgetEntitiesViz';
import type { Widget, WidgetVizConfig } from '../../../utils/widget/widget';

interface WidgetVizProps {
  widget: Widget;
  config: WidgetVizConfig;
  popover?: ReactNode;
}

const WidgetViz = ({ widget, config, popover }: WidgetVizProps) => {
  const { perspective } = widget;
  return (
    <ErrorBoundary>
      <>
        {perspective === 'entities' && (
          <WidgetEntitiesViz widget={widget} config={config} popover={popover} />
        )}
        {perspective === 'relationships' && (
          <WidgetRelationshipsViz widget={widget} config={config} popover={popover} />
        )}
        {perspective === 'audits' && (
          <WidgetAuditsViz widget={widget} config={config} popover={popover} />
        )}
        {perspective === null && (
          <WidgetRawViz widget={widget} popover={popover} />
        )}
      </>
    </ErrorBoundary>
  );
};

export default WidgetViz;
