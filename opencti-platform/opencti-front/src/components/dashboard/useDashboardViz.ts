import type {
  WidgetDataSelection,
  WidgetPerspective,
  WidgetHost,
  WidgetParameters,
} from '../../utils/widget/widget';
import { useCallback, useEffect, useMemo, useRef, useState, useTransition } from 'react';
import { useDashboardRefreshToken, useDashboardSetQueryPending } from './DashboardRefreshContext';
import { DashboardConfig } from './dashboard-types';
import { useQueryLoader } from 'react-relay';
import type { GraphQLTaggedNode, OperationType } from 'relay-runtime';
import useAuth from '../../utils/hooks/useAuth';
import { resolveDataSelection } from './dashboardVizUtils';

const useDashboardViz = <TQuery extends OperationType>({
  dataSelection,
  perspective,
  host,
  query,
  buildQueryVariables,
  parameters,
  config,
}: {
  dataSelection: WidgetDataSelection[];
  perspective: WidgetPerspective;
  host?: WidgetHost;
  // Accepted for backward compatibility with widget props; no longer used for
  // scheduling (refresh is driven centrally by the refreshToken context).
  refreshRate?: number | null;
  query: GraphQLTaggedNode;
  config?: DashboardConfig;
  parameters?: WidgetParameters;
  buildQueryVariables?: (
    resolvedDataSelection: WidgetDataSelection[],
    config: DashboardConfig,
    parameters?: WidgetParameters,
  ) => TQuery['variables'];
}) => {
  const [queryRef, load, disposeQuery] = useQueryLoader<TQuery>(query);
  const [isPending, startTransition] = useTransition();
  const lastLoadedVariablesSignatureRef = useRef<string | null>(null);
  const setQueryPending = useDashboardSetQueryPending();
  const queryIdRef = useRef(`dashboard-viz-${Math.random().toString(36).slice(2)}`);

  // Resolve data selection
  const { filterKeysSchema } = useAuth().schema;
  const [resolvedDataSelection, setResolvedDataSelection] = useState<WidgetDataSelection[]>([]);
  const [isMissingHostEntity, setIsMissingHostEntity] = useState(false);
  const [isPreviewMode, setIsPreviewMode] = useState(false);
  const [isMissingSavedFilters, setIsMissingSavedFilters] = useState(false);

  // refreshToken is an integer provided via context by DashboardContent and incremented
  // by CustomDashboard on manual or auto refresh. When it changes, we force-reload
  // regardless of whether query variables changed, so fresh data is always fetched.
  // prevRefreshTokenRef guards against triggering on the initial mount.
  const refreshToken = useDashboardRefreshToken();
  const prevRefreshTokenRef = useRef(refreshToken);

  // Stabilize the dataSelection dependency to avoid re-triggering the effect
  // on every render when the parent passes a new array reference with the same content.
  const dataSelectionSignature = useMemo(() => JSON.stringify(dataSelection), [dataSelection]);

  /**
   * Resolve raw data selection into a query-ready form.
   *
   * Hydrates saved filters, injects host entity context, and updates edge-case flags
   * (`isMissingHostEntity`, `isPreviewMode`, `isMissingSavedFilters`).
   *
   * When provided, `onResolved` runs after state updates with the fresh resolution
   * result so callers can avoid stale closure values.
   */
  const handleResolveDataSelection = useCallback(
    (onResolved?: (result: Awaited<ReturnType<typeof resolveDataSelection>>) => void) => {
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
          onResolved?.(result);
        }
      });
      return () => {
        cancelled = true;
      };
    },
    [filterKeysSchema, dataSelectionSignature, perspective, host],
  );

  // Re-resolve selection inputs when schema, selection content, perspective, or host changes
  // Because those changes make the result change
  useEffect(handleResolveDataSelection, [handleResolveDataSelection]);

  const queryVariables = useMemo(
    () =>
      buildQueryVariables && config && resolvedDataSelection.length > 0
        ? buildQueryVariables(resolvedDataSelection, config, parameters)
        : null,
    [buildQueryVariables, resolvedDataSelection, config, parameters],
  );

  const queryVariablesSignature = useMemo(
    () => (queryVariables ? JSON.stringify(queryVariables) : null),
    [queryVariables],
  );

  const loadAndTrackSignature = useCallback(
    (variables: TQuery['variables'], signature: string) => {
      lastLoadedVariablesSignatureRef.current = signature;
      startTransition(() => {
        load(variables, {
          fetchPolicy: 'store-and-network',
        });
      });
    },
    [load, startTransition],
  );

  const reloadData = useCallback(
    (force = false) => {
      if (isMissingHostEntity) {
        return;
      }

      if (isMissingSavedFilters) {
        return;
      }

      if (!queryVariables || !queryVariablesSignature) {
        return;
      }

      if (!force && queryVariablesSignature === lastLoadedVariablesSignatureRef.current) {
        return;
      }

      loadAndTrackSignature(queryVariables, queryVariablesSignature);
    },
    [
      isMissingHostEntity,
      isMissingSavedFilters,
      queryVariables,
      queryVariablesSignature,
      loadAndTrackSignature,
    ],
  );

  useEffect(() => {
    if (!isMissingHostEntity || !isMissingSavedFilters) {
      return;
    }
    lastLoadedVariablesSignatureRef.current = null;
    disposeQuery();
  }, [disposeQuery, isMissingHostEntity, isMissingSavedFilters]);

  useEffect(() => {
    reloadData(false);
  }, [reloadData]);

  // Expose this widget's in-flight status so the dashboard can lock the manual
  // refresh button until every widget has finished refreshing.
  useEffect(() => {
    const queryId = queryIdRef.current;
    setQueryPending(queryId, isPending);
    return () => setQueryPending(queryId, false);
  }, [isPending, setQueryPending]);

  /**
   * Rebuild query variables from the latest resolved selection and force a reload.
   *
   * Used by dashboard token refresh to avoid relying on a possibly stale
   * `resolvedDataSelection` closure value.
   */
  const forceReloadWithFreshVariables = useCallback(
    (selection: WidgetDataSelection[] = resolvedDataSelection) => {
      if (!buildQueryVariables || !config || selection.length === 0) {
        reloadData(true);
        return;
      }

      const refreshedVariables = buildQueryVariables(selection, config, parameters);
      const refreshedSignature = JSON.stringify(refreshedVariables);
      loadAndTrackSignature(refreshedVariables, refreshedSignature);
    },
    [
      buildQueryVariables,
      config,
      resolvedDataSelection,
      parameters,
      reloadData,
      loadAndTrackSignature,
    ],
  );

  useEffect(() => {
    if (prevRefreshTokenRef.current === refreshToken) return undefined;
    prevRefreshTokenRef.current = refreshToken;

    if (isMissingHostEntity || isMissingSavedFilters) {
      return undefined;
    }

    /**
     * Re-resolve data selection on refresh, then force reload
     * with the freshly resolved data selection.
     */
    return handleResolveDataSelection((result) => {
      if (result.isMissingHostEntity || result.isMissingSavedFilters) {
        return;
      }
      forceReloadWithFreshVariables(result.resolvedDataSelection);
    });
  }, [
    refreshToken,
    isMissingHostEntity,
    isMissingSavedFilters,
    forceReloadWithFreshVariables,
    handleResolveDataSelection,
  ]);

  return {
    queryRef,
    isPreviewMode,
    resolvedDataSelection,
    isMissingHostEntity,
    isMissingSavedFilters,
  };
};

export default useDashboardViz;
