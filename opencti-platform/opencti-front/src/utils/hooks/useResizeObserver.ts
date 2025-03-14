import { type MutableRefObject, useEffect, useState } from 'react';
import callbackResizeObserver from '../resizeObservers';

const useResizeObserver = (ref: MutableRefObject<HTMLDivElement | null>) => {
  const [width, setWidth] = useState(0);
  const [height, setHeight] = useState(0);

  useEffect(() => {
    let observer: ResizeObserver;
    const setSize = () => {
      if (ref.current) {
        setWidth(ref.current.offsetWidth);
        setHeight(ref.current.offsetHeight);
      }
    };
    if (ref.current) {
      observer = callbackResizeObserver(ref.current, setSize);
    }
    return () => { observer?.disconnect(); };
  }, [ref]);

  return { width, height };
};

export default useResizeObserver;
