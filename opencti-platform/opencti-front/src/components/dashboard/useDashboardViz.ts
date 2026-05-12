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
  const { resolvedDataSelection, isMissingHostEntity, isPreviewMode } = resolveDataSelection({
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
