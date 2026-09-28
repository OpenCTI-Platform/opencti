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
  // The baseline and the paused state survive effect re-runs; everything tied to
  // a single run (timer, in-flight check, cancellation) is local to that run so a
  // check started by a previous run can never act after its cleanup.
  const baselineRef = useRef<RevisionByCatalogId | null>(null);
  const wasPausedRef = useRef(false);

  useEffect(() => {
    if (!enabled) {
      return undefined;
    }

    let cancelled = false;
    let isCheckInFlight = false;
    let timeout: ReturnType<typeof setTimeout> | null = null;

    const clearScheduledCheck = () => {
      if (timeout) {
        clearTimeout(timeout);
        timeout = null;
      }
    };

    const scheduleNextCheck = () => {
      if (cancelled || document.hidden) {
        return;
      }
      clearScheduledCheck();
      timeout = setTimeout(() => {
        void checkCatalogRevisions();
      }, CATALOG_POLLING_INTERVAL_MS);
    };

    const checkCatalogRevisions = async () => {
      if (isCheckInFlight || cancelled || document.hidden) {
        return;
      }
      isCheckInFlight = true;
      try {
        const result = await fetchQuery<IngestionConnectorsCatalogRevisionsQuery>(
          ingestionConnectorsCatalogRevisionsQuery,
          {},
          { fetchPolicy: 'network-only' },
        ).toPromise().catch(() => null);

        if (!result || cancelled) {
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

        try {
          await onCatalogRevisionsChanged();
        } catch {
          // Keep the previous baseline so the next check detects the change again and retries.
          return;
        }
        baselineRef.current = nextBaseline;
      } finally {
        isCheckInFlight = false;
        scheduleNextCheck();
      }
    };

    const onVisibilityChange = () => {
      if (document.hidden) {
        wasPausedRef.current = true;
        clearScheduledCheck();
        return;
      }
      if (wasPausedRef.current || !baselineRef.current) {
        wasPausedRef.current = false;
        void checkCatalogRevisions();
      }
    };

    document.addEventListener('visibilitychange', onVisibilityChange);
    void checkCatalogRevisions();

    return () => {
      cancelled = true;
      clearScheduledCheck();
      document.removeEventListener('visibilitychange', onVisibilityChange);
    };
  }, [enabled, onCatalogRevisionsChanged]);
};

export default useCatalogPolling;
