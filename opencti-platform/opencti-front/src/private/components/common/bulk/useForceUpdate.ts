import { useState } from 'react';

type UseForceUpdateType = {
  forceUpdate: string;
  handleForceUpdate: () => void;
};

const useForceUpdate = (): UseForceUpdateType => {
  const [forceUpdate, setForceUpdate] = useState(String(new Date()));

  const handleForceUpdate = () => setForceUpdate(String(new Date()));

  return {
    forceUpdate,
    handleForceUpdate,
  };
};

export default useForceUpdate;
