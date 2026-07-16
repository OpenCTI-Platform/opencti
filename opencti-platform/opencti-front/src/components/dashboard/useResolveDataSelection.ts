import type { WidgetHost, WidgetDataSelection, WidgetPerspective } from '../../utils/widget/widget';
import useAuth from '../../utils/hooks/useAuth';
import { resolveDataSelection } from './dashboardVizUtils';
import { useEffect, useMemo, useState } from 'react';

/**
 * Hook that resolves widget data selections (filter cleaning, saved filter resolution,
 * host entity substitution). Use this when you only need resolved data selections
 * without query loading (e.g. widgets that manage their own queries).
 */
const useResolveDataSelection = ({
  dataSelection,
  perspective,
  host,
}: {
  dataSelection: WidgetDataSelection[];
  perspective: WidgetPerspective;
  host?: WidgetHost;
}) => {
  const { filterKeysSchema } = useAuth().schema;

  const [resolvedDataSelection, setResolvedDataSelection] = useState<WidgetDataSelection[]>([]);
  const [isMissingHostEntity, setIsMissingHostEntity] = useState(false);
  const [isPreviewMode, setIsPreviewMode] = useState(false);
  const [isMissingSavedFilters, setIsMissingSavedFilters] = useState(false);

  // Stabilize the dataSelection dependency to avoid re-triggering the effect
  // on every render when the parent passes a new array reference with the same content.
  const dataSelectionSignature = useMemo(() => JSON.stringify(dataSelection), [dataSelection]);

  useEffect(() => {
    let cancelled = false;
    resolveDataSelection({
      filterKeysSchema,
      dataSelection,
      perspective,
      host,
    }).then((result) => {
      if (!cancelled) {
        setResolvedDataSelection(result.resolvedDataSelection);
        setIsMissingHostEntity(result.isMissingHostEntity);
        setIsPreviewMode(result.isPreviewMode);
        setIsMissingSavedFilters(result.isMissingSavedFilters);
      }
    });
    return () => {
      cancelled = true;
    };
  }, [filterKeysSchema, dataSelectionSignature, perspective, host]);

  return {
    resolvedDataSelection,
    isMissingHostEntity,
    isPreviewMode,
    isMissingSavedFilters,
  };
};

export default useResolveDataSelection;
