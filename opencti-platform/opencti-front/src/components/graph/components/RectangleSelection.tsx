import React, { ReactNode, useState } from 'react';
import RectangleSelectionLib from 'react-rectangle-selection';
import { useTheme } from '@mui/material/styles';
import { hexToRGB } from '../../../utils/Colors';
import type { Theme } from '../../Theme';

interface RectangleCoordinates {
  origin: [number, number];
  target: [number, number];
}

interface RectangleKeys {
  altKey: boolean;
  shiftKey: boolean;
}

export interface RectangleSelectionProps {
  graphId: string;
  children: ReactNode;
  onSelection: (coords: RectangleCoordinates, keys: RectangleKeys) => void;
  disabled?: boolean;
}

const RectangleSelection = ({
  graphId,
  children,
  onSelection,
  disabled = false,
}: RectangleSelectionProps) => {
  const theme = useTheme<Theme>();
  const [coords, setCoords] = useState<RectangleCoordinates | null>(null);
  const [keys, setKeys] = useState<RectangleKeys>({ altKey: false, shiftKey: false });

  const updateStateOnSelect = (
    { altKey, shiftKey }: MouseEvent,
    selectionCoords: RectangleCoordinates,
  ) => {
    if (!disabled) {
      setKeys({ altKey, shiftKey });
      const graphCanvas = document.querySelector(`#${graphId} canvas`);
      if (graphCanvas) {
        const { left, top } = graphCanvas.getBoundingClientRect();
        // The library provides page coordinates (pageX/pageY) but
        // getBoundingClientRect() is viewport-relative; account for scroll.
        const offsetLeft = left + window.scrollX;
        const offsetTop = top + window.scrollY;
        setCoords({
          origin: [
            Math.min(selectionCoords.origin[0], selectionCoords.target[0]) - offsetLeft,
            Math.min(selectionCoords.origin[1], selectionCoords.target[1]) - offsetTop,
          ],
          target: [
            Math.max(selectionCoords.origin[0], selectionCoords.target[0]) - offsetLeft,
            Math.max(selectionCoords.origin[1], selectionCoords.target[1]) - offsetTop,
          ],
        });
      }
    }
  };

  const sendState = () => {
    if (!disabled && coords) onSelection(coords, keys);
    setCoords(null);
  };

  const overlayColor = theme.palette.background?.accent
    ? hexToRGB(theme.palette.background.accent, 0.3)
    : theme.palette.warn.main;
  const borderColor = theme.palette.warn.main;

  return (
    <RectangleSelectionLib
      style={{
        // Hide the library's built-in selection box: it uses pageX/pageY as
        // CSS left/top which is incorrect when the graph is not at the
        // document origin (e.g. behind a side-nav or top-bar).
        display: 'none',
      }}
      disabled={disabled}
      onMouseUp={sendState}
      onSelect={updateStateOnSelect}
    >
      <div style={{ position: 'relative', height: 'inherit', width: 'inherit' }}>
        {/* Render our own overlay positioned relative to the graph container */}
        {coords && (
          <div
            style={{
              position: 'absolute',
              left: coords.origin[0],
              top: coords.origin[1],
              width: coords.target[0] - coords.origin[0],
              height: coords.target[1] - coords.origin[1],
              backgroundColor: overlayColor,
              border: `1px dashed ${borderColor}`,
              pointerEvents: 'none',
              zIndex: 10,
            }}
          />
        )}
        {children}
      </div>
    </RectangleSelectionLib>
  );
};

export default RectangleSelection;
