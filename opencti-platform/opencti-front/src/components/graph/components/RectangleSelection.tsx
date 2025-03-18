import React, { ReactNode, useState } from 'react';
import RectangleSelectionLib from 'react-rectangle-selection';
import { useTheme } from '@mui/material/styles';
import { hexToRGB } from '../../../utils/Colors';
import type { Theme } from '../../Theme';

interface RectangleCoordinates {
  origin: [number, number]
  target: [number, number]
}

interface RectangleKeys {
  altKey: boolean
  shiftKey: boolean
}

export interface RectangleSelectionProps {
  graphId: string
  children: ReactNode
  onSelection: (coords: RectangleCoordinates, keys: RectangleKeys) => void
  disabled?: boolean
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
        setCoords({
          origin: [
            Math.min(selectionCoords.origin[0], selectionCoords.target[0]) - left,
            Math.min(selectionCoords.origin[1], selectionCoords.target[1]) - top,
          ],
          target: [
            Math.max(selectionCoords.origin[0], selectionCoords.target[0]) - left,
            Math.max(selectionCoords.origin[1], selectionCoords.target[1]) - top,
          ],
        });
      }
    }
  };

  const sendState = () => {
    if (!disabled && coords) onSelection(coords, keys);
    setCoords(null);
  };

  return (
    <RectangleSelectionLib
      style={{
        backgroundColor: hexToRGB(theme.palette.background.accent, 0.3),
        borderColor: theme.palette.warn.main,
      }}
      disabled={disabled}
      onMouseUp={sendState}
      onSelect={updateStateOnSelect}
    >
      {children}
    </RectangleSelectionLib>
  );
};

export default RectangleSelection;
