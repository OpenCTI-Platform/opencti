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
  revisions: ReadonlyArray<{ catalog_id: string; revision: string | null | undefined }> | null | undefined,
): RevisionByCatalogId => {
  return new Map((revisions ?? []).map((entry) => [entry.catalog_id, entry.revision ?? null]));
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
        void checkCatalogRevisions();
      }, CATALOG_POLLING_INTERVAL_MS);
    };

    const checkCatalogRevisions = async () => {
      if (isCheckInFlightRef.current || isUnmountedRef.current || document.hidden) {
        return;
      }
      isCheckInFlightRef.current = true;
      try {
        const result = await fetchQuery<IngestionConnectorsCatalogRevisionsQuery>(
          ingestionConnectorsCatalogRevisionsQuery,
          {},
          { fetchPolicy: 'network-only' },
        ).toPromise().catch(() => null);

        if (!result) {
          return;
        }

        const nextBaseline = toRevisionMap(result.catalogsRevisions ?? []);

        if (!baselineRef.current) {
          baselineRef.current = nextBaseline;
          return;
        }

        if (!haveRevisionsChanged(baselineRef.current, nextBaseline)) {
          return;
        }

        await onCatalogRevisionsChanged();
        baselineRef.current = nextBaseline;
      } finally {
        isCheckInFlightRef.current = false;
        scheduleNextCheck();
      }
    };

    const onVisibilityChange = () => {
      if (document.hidden) {
        wasPausedRef.current = true;
        clearScheduledCheck();
        return;
      }
      if (wasPausedRef.current) {
        wasPausedRef.current = false;
        void checkCatalogRevisions();
      }
    };

    document.addEventListener('visibilitychange', onVisibilityChange);
    void checkCatalogRevisions();

    return () => {
      isUnmountedRef.current = true;
      clearScheduledCheck();
      document.removeEventListener('visibilitychange', onVisibilityChange);
    };
  }, [enabled, onCatalogRevisionsChanged]);
};

export default useCatalogPolling;
