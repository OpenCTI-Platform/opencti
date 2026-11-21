import { useEffect, useState } from 'react';
import { type ReactFlowState, useStore } from 'reactflow';

/** Below this zoom level, nodes drop secondary text and edges drop their labels. */
export const COMPACT_ZOOM = 0.5;

const compactSelector = (state: ReactFlowState) => state.transform[2] < COMPACT_ZOOM;

/** Level of detail: a boolean selector, so components only re-render when the threshold is crossed. */
export const useCompactMode = () => useStore(compactSelector);

export const useZoomPercent = () => useStore((state: ReactFlowState) => Math.round(state.transform[2] * 100));

/** Frames per second, sampled once a second. Only meant for the dev build. */
export const useFps = (enabled: boolean) => {
  const [fps, setFps] = useState<number | null>(null);
  useEffect(() => {
    if (!enabled) return undefined;
    let frames = 0;
    let last = performance.now();
    let handle = requestAnimationFrame(function tick(now) {
      frames += 1;
      if (now - last >= 1000) {
        setFps(Math.round((frames * 1000) / (now - last)));
        frames = 0;
        last = now;
      }
      handle = requestAnimationFrame(tick);
    });
    return () => cancelAnimationFrame(handle);
  }, [enabled]);
  return fps;
};
