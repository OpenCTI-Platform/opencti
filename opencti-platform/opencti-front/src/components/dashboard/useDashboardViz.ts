import type { WidgetHost, WidgetDataSelection, WidgetPerspective } from '../../utils/widget/widget';
import useAuth from '../../utils/hooks/useAuth';
import { resolveDataSelection } from './dashboard-viz-utils';

const useDashboardViz = ({
  dataSelection,
  perspective,
  host,
}: {
  dataSelection: WidgetDataSelection[];
  perspective: WidgetPerspective;
  host?: WidgetHost;
}) => {
  const { filterKeysSchema } = useAuth().schema;
  const isPreviewMode = host?.kind === 'custom-view' && host.previewMode;
  const { resolvedDataSelection, isMissingHostEntity } = resolveDataSelection({
    filterKeysSchema,
    dataSelection,
    perspective,
    host,
  });
  return {
    isPreviewMode,
    resolvedDataSelection,
    isMissingHostEntity,
  };
};

export default useDashboardViz;
