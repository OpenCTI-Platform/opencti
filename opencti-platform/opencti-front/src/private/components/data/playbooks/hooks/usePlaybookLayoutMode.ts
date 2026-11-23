import { createContext, useCallback, useContext, useState } from 'react';
import { Position } from 'reactflow';

// The direction the canvas is laid out in, remembered per playbook in the browser.
export type PlaybookLayoutDirection = 'vertical' | 'horizontal';

const storageKey = (playbookId: string) => `playbook-layout-direction-${playbookId}`;

const readDirection = (playbookId: string): PlaybookLayoutDirection => {
  try {
    return window.localStorage.getItem(storageKey(playbookId)) === 'horizontal' ? 'horizontal' : 'vertical';
  } catch {
    return 'vertical';
  }
};

export const usePlaybookLayoutMode = (playbookId: string) => {
  const [direction, setDirectionState] = useState<PlaybookLayoutDirection>(() => readDirection(playbookId));
  const setDirection = useCallback((next: PlaybookLayoutDirection) => {
    setDirectionState(next);
    try {
      window.localStorage.setItem(storageKey(playbookId), next);
    } catch {
      // storage refused (private mode): the choice lasts for the session only
    }
  }, [playbookId]);
  return { direction, setDirection };
};

export const PlaybookLayoutDirectionContext = createContext<PlaybookLayoutDirection>('vertical');

// Where the links enter a node and where they leave it, for the current direction.
export const usePlaybookHandlePositions = () => {
  const direction = useContext(PlaybookLayoutDirectionContext);
  return direction === 'horizontal'
    ? { direction, target: Position.Left, source: Position.Right }
    : { direction, target: Position.Top, source: Position.Bottom };
};
