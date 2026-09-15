import { useEffect, useRef } from 'react';
import { fetchQuery } from '../../../../../relay/environment';
import { ingestionConnectorsCatalogRevisionsQuery } from '../IngestionConnectorsCatalog';
import { CATALOG_POLLING_INTERVAL_MS } from '../catalog-constants';
import type { IngestionConnectorsCatalogRevisionsQuery } from '../__generated__/IngestionConnectorsCatalogRevisionsQuery.graphql';

type UseCatalogPollingProps = {
  enabled: boolean;
  onCatalogRevisionsChanged: () => Promise<void> | void;
};

type RevisionByCatalogId = Map<string, string | null>;

const toRevisionMap = (
  revisions: ReadonlyArray<{ id: string; revision: string | null }> | null | undefined,
): RevisionByCatalogId => {
  return new Map((revisions ?? []).map((entry) => [entry.id, entry.revision]));
};

const haveRevisionsChanged = (baseline: RevisionByCatalogId, next: RevisionByCatalogId): boolean => {
  if (baseline.size !== next.size) {
    return true;
  }
  for (const [catalogId, revision] of next) {
    if (!baseline.has(catalogId) || baseline.get(catalogId) !== revision) {
      return true;
    }
  }
  return false;
};

const useCatalogPolling = ({ enabled, onCatalogRevisionsChanged }: UseCatalogPollingProps) => {
  const baselineRef = useRef<RevisionByCatalogId | null>(null);
  const timeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const isUnmountedRef = useRef(false);
  const isCheckInFlightRef = useRef(false);
  const wasPausedRef = useRef(false);

  useEffect(() => {
    if (!enabled) {
      return undefined;
    }

    isUnmountedRef.current = false;

    const clearScheduledCheck = () => {
      if (timeoutRef.current) {
        clearTimeout(timeoutRef.current);
        timeoutRef.current = null;
      }
    };

    const scheduleNextCheck = () => {
      if (isUnmountedRef.current || document.hidden) {
        return;
      }
      clearScheduledCheck();
      timeoutRef.current = setTimeout(() => {
        void checkCatalogRevisions('interval');
      }, CATALOG_POLLING_INTERVAL_MS);
    };

    const checkCatalogRevisions = async (reason: 'seed' | 'interval' | 'visibility-resume') => {
      if (isCheckInFlightRef.current || isUnmountedRef.current || document.hidden) {
        return;
      }
      isCheckInFlightRef.current = true;
      try {
        const result = await fetchQuery<IngestionConnectorsCatalogRevisionsQuery>(
          ingestionConnectorsCatalogRevisionsQuery,
          {},
        ).toPromise();
        const nextBaseline = toRevisionMap(result?.catalogsRevisions ?? []);

        if (!baselineRef.current) {
          baselineRef.current = nextBaseline;
          console.log('[CatalogPolling] baseline seeded', {
            reason,
            catalogsCount: nextBaseline.size,
          });
          return;
        }

        if (!haveRevisionsChanged(baselineRef.current, nextBaseline)) {
          console.log('[CatalogPolling] no revision change', {
            reason,
            catalogsCount: nextBaseline.size,
          });
          return;
        }

        console.log('[CatalogPolling] revision change detected, refreshing catalogs', {
          reason,
          catalogsCount: nextBaseline.size,
        });

        await onCatalogRevisionsChanged();
        baselineRef.current = nextBaseline;
      } catch (error) {
        console.log('[CatalogPolling] revisions check failed', { reason, error });
      } finally {
        isCheckInFlightRef.current = false;
        scheduleNextCheck();
      }
    };

    const onVisibilityChange = () => {
      if (document.hidden) {
        wasPausedRef.current = true;
        clearScheduledCheck();
        console.log('[CatalogPolling] polling paused (tab hidden)');
        return;
      }
      if (wasPausedRef.current) {
        wasPausedRef.current = false;
        console.log('[CatalogPolling] polling resumed, checking now');
        void checkCatalogRevisions('visibility-resume');
      }
    };

    document.addEventListener('visibilitychange', onVisibilityChange);
    void checkCatalogRevisions('seed');

    return () => {
      isUnmountedRef.current = true;
      clearScheduledCheck();
      document.removeEventListener('visibilitychange', onVisibilityChange);
      console.log('[CatalogPolling] stopped');
    };
  }, [enabled, onCatalogRevisionsChanged]);
};

export default useCatalogPolling;
