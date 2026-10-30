import { useEffect, useRef } from 'react';
import useEnterpriseEdition from '../../../../utils/hooks/useEnterpriseEdition';

export const CONFIG_PRESET_LICENSE_RETRY_DELAY_MS = 1500;
export const CONFIG_PRESET_LICENSE_MAX_RETRIES = 3;

// The front end knows the platform has the Enterprise Edition (a license was just activated) while the backend still locks a type:
// the backend may not have refreshed its settings yet (on a cluster the refresh travels by pub/sub). The types are read again a few times.
// Pass the types as loaded, not rebuilt on each render: a new array restarts the delay.
const useConfigPresetLicenseRetry = (types: ReadonlyArray<{ readonly locked: boolean }> | null | undefined, reload: () => void) => {
  const isEnterpriseEdition = useEnterpriseEdition();
  const attemptsRef = useRef(0);
  const reloadRef = useRef(reload);
  reloadRef.current = reload;
  const isStale = isEnterpriseEdition && !!types?.some((type) => type.locked);

  useEffect(() => {
    if (!isStale) {
      attemptsRef.current = 0;
      return undefined;
    }
    if (attemptsRef.current >= CONFIG_PRESET_LICENSE_MAX_RETRIES) {
      return undefined;
    }
    const timer = window.setTimeout(() => {
      attemptsRef.current += 1;
      reloadRef.current();
    }, CONFIG_PRESET_LICENSE_RETRY_DELAY_MS);
    return () => window.clearTimeout(timer);
  }, [isStale, types]);
};

export default useConfigPresetLicenseRetry;
