import React, { ReactNode, useSyncExternalStore } from 'react';
import { isReloadingForStaleChunk, onStaleChunkReloadCanceled } from '../../utils/staleChunkReload';

interface StaleChunkReloadGateProps {
  error: unknown;
  children: ReactNode;
}

// Hides an error while the page reloads to the new build for it, and shows it again
// when the reload is canceled
const StaleChunkReloadGate = ({ error, children }: StaleChunkReloadGateProps) => {
  const reloading = useSyncExternalStore(onStaleChunkReloadCanceled, () => isReloadingForStaleChunk(error));
  return reloading ? null : <>{children}</>;
};

export default StaleChunkReloadGate;
