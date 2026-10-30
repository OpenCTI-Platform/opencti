import { useCallback, useEffect, useRef, useState } from 'react';
import useEnterpriseEdition from '../../../../utils/hooks/useEnterpriseEdition';

export const CONFIG_PRESET_LICENSE_RETRY_DELAY_MS = 1500;
export const CONFIG_PRESET_LICENSE_MAX_RETRIES = 3;

// The front end knows the platform has the Enterprise Edition (a license was just activated) while the backend still locks a type:
// the backend may not have refreshed its settings yet (on a cluster the refresh travels by pub/sub). The types are read again a few times,
// each attempt after the previous one, whether or not the answer looks different. Returns what reads them at once and counts again,
// for the user who clicks after the last attempt.
const useConfigPresetLicenseRetry = (types: ReadonlyArray<{ readonly lockedByEnterpriseEdition: boolean }> | null | undefined, reload: () => void): (() => void) => {
  const isEnterpriseEdition = useEnterpriseEdition();
  const [attempt, setAttempt] = useState(0);
  const reloadRef = useRef(reload);
  reloadRef.current = reload;
  const isStale = isEnterpriseEdition && !!types?.some((type) => type.lockedByEnterpriseEdition);

  useEffect(() => {
    if (!isStale) {
      setAttempt(0);
      return undefined;
    }
    if (attempt >= CONFIG_PRESET_LICENSE_MAX_RETRIES) {
      return undefined;
    }
    const timer = window.setTimeout(() => {
      setAttempt((count) => count + 1);
      reloadRef.current();
    }, CONFIG_PRESET_LICENSE_RETRY_DELAY_MS);
    return () => window.clearTimeout(timer);
  }, [isStale, attempt]);

  return useCallback(() => {
    setAttempt(0);
    reloadRef.current();
  }, []);
};

export default useConfigPresetLicenseRetry;
