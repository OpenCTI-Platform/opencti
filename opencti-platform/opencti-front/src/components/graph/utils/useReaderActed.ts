import { type MutableRefObject, useEffect, useRef } from 'react';

const READER_EVENTS = ['pointerdown', 'wheel', 'keydown'] as const;

/**
 * Whether the reader acted on the page (a click, a key, a zoom) since the graph was last shown in
 * its current mode, so that an automatic framing never moves the view under the pointer.
 * Switching between 2D and 3D starts over; the end of the loading of the data does not, so what
 * the reader did while it ran still counts. `onAction` runs on every action.
 */
const useReaderActed = (mode3D: boolean, onAction?: () => void): MutableRefObject<boolean> => {
  const acted = useRef(false);
  const latestOnAction = useRef(onAction);
  latestOnAction.current = onAction;

  useEffect(() => {
    const onReaderAction = () => {
      acted.current = true;
      latestOnAction.current?.();
    };
    READER_EVENTS.forEach((event) => window.addEventListener(event, onReaderAction, true));
    return () => READER_EVENTS.forEach((event) => window.removeEventListener(event, onReaderAction, true));
  }, []);

  useEffect(() => {
    acted.current = false;
  }, [mode3D]);

  return acted;
};

export default useReaderActed;
