import { useEffect, useState } from 'react';
import { fetchCaseRfiNodeIds } from '@components/cases/caseRfiNodeIdsApi';
import { fetchCaseRfiSlaByIds } from '@components/nav/slaExpiry/caseRfiSlaApi';
import type { CaseRfiSlaRemainingTimeSnapshot } from '@components/nav/slaExpiry/caseRfiSlaMetricsUtils';
import { mapCaseRfiSlaResponseToRemainingById } from '@components/nav/slaExpiry/caseRfiSlaMetricsUtils';

const useCaseRfiSlaRemainingById = (): Record<string, CaseRfiSlaRemainingTimeSnapshot> => {
  const [remainingById, setRemainingById] = useState<Record<string, CaseRfiSlaRemainingTimeSnapshot>>({});

  useEffect(() => {
    let cancelled = false;

    const load = async () => {
      try {
        const openctiIds = await fetchCaseRfiNodeIds();
        const slaResponse = await fetchCaseRfiSlaByIds(openctiIds);
        const mapped = mapCaseRfiSlaResponseToRemainingById(slaResponse, openctiIds);

        if (!cancelled) {
          setRemainingById(mapped);
        }
      } catch {
        if (!cancelled) {
          setRemainingById({});
        }
      }
    };

    void load();

    return () => {
      cancelled = true;
    };
  }, []);

  return remainingById;
};

export default useCaseRfiSlaRemainingById;
