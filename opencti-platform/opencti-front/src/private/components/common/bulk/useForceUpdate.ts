import { useEffect, useState, useCallback } from 'react';

type UseForceUpdateType = {
  forceUpdate: string;
};

export const ForceUpdateEvent = 'ForceUpdateEvent';

const useForceUpdate = (): UseForceUpdateType => {
  const [forceUpdate, setForceUpdate] = useState(String(new Date()));

  const onForceUpdateEventTriggered = useCallback(() => setForceUpdate(String(new Date())), [setForceUpdate]);

  useEffect(() => {
    window.addEventListener(ForceUpdateEvent, onForceUpdateEventTriggered);
    return () => window.removeEventListener(ForceUpdateEvent, onForceUpdateEventTriggered);
  }, []);

  return {
    forceUpdate,
  };
};

export default useForceUpdate;
