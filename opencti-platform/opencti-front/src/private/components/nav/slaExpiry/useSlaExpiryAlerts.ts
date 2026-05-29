import { useEffect, useState } from 'react';
import type { SlaExpiryAlertItem } from './slaExpiryTypes';
import { fetchSlaExpiryAlerts } from './slaExpiryMockData';

const useSlaExpiryAlerts = (): SlaExpiryAlertItem[] => {
  const [items, setItems] = useState<SlaExpiryAlertItem[]>([]);

  useEffect(() => {
    let cancelled = false;

    const load = async () => {
      try {
        const alerts = await fetchSlaExpiryAlerts();
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
  }, []);

  return items;
};

export default useSlaExpiryAlerts;
