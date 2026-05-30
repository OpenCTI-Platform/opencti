import { useEffect, useState } from 'react';
import { useLocation } from 'react-router-dom';
import { fetchCaseRfiNodeIds } from '@components/cases/caseRfiNodeIdsApi';
import type { SlaExpiryAlertItem } from './slaExpiryTypes';
import { fetchCaseRfiSlaByIds } from './caseRfiSlaApi';
import { mapCaseRfiSlaResponseToAlerts } from './slaExpiryMapper';

const useSlaExpiryAlerts = (): SlaExpiryAlertItem[] => {
  const { pathname } = useLocation();
  const [items, setItems] = useState<SlaExpiryAlertItem[]>([]);

  useEffect(() => {
    let cancelled = false;

    const load = async () => {
      try {
        const openctiIds = await fetchCaseRfiNodeIds();
        const slaResponse = await fetchCaseRfiSlaByIds(openctiIds);
        const alerts = mapCaseRfiSlaResponseToAlerts(slaResponse);

        if (!cancelled) {
          setItems(alerts);
        }
      } catch {
        if (!cancelled) {
          setItems([]);
        }
      }
    };

    void load();

    return () => {
      cancelled = true;
    };
  }, [pathname]);

  return items;
};

export default useSlaExpiryAlerts;
