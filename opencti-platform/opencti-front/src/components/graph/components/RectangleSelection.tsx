import React, { MouseEvent as ReactMouseEvent, ReactNode, useEffect, useRef, useState } from 'react';
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
  children: ReactNode;
  onSelection: (coords: RectangleCoordinates, keys: RectangleKeys) => void;
  disabled?: boolean;
}

interface Selection extends RectangleCoordinates {
  keys: RectangleKeys;
}

/**
 * Project a pointer position into the coordinate system of the graph canvas.
 * getBoundingClientRect() and clientX/clientY are both viewport-relative, so
 * no scroll compensation is needed here.
 */
const canvasPoint = (
  { clientX, clientY }: { clientX: number; clientY: number },
  rect: DOMRect | null,
): [number, number] => {
  const { left, top } = rect ?? { left: 0, top: 0 };
  return [clientX - left, clientY - top];
};

/**
 * Order the two corners of a drag into a top-left / bottom-right pair, so
 * consumers always receive a normalized rectangle whatever the direction
 * the user dragged in.
 */
const normalize = ({ origin, target }: RectangleCoordinates): RectangleCoordinates => ({
  origin: [Math.min(origin[0], target[0]), Math.min(origin[1], target[1])],
  target: [Math.max(origin[0], target[0]), Math.max(origin[1], target[1])],
});

/**
 * Draw a selection rectangle over the graph and hand its coordinates over
 * once the drag is released.
 *
 * Coordinates are relative to the graph canvas, as consumers convert them
 * back to graph space with ForceGraphMethods.screen2GraphCoords().
 */
const RectangleSelection = ({
  children,
  onSelection,
  disabled = false,
}: RectangleSelectionProps) => {
  const theme = useTheme<Theme>();
  const [selection, setSelection] = useState<Selection | null>(null);
  const [isDragging, setIsDragging] = useState(false);
  // Bounding box of the graph canvas, read once when the drag starts to
  // avoid a layout measurement on every mouse move.
  const canvasRect = useRef<DOMRect | null>(null);
  // Origin of the ongoing drag. Kept out of the state so that a plain click
  // does not draw a rectangle: the selection only exists once the mouse moved.
  const dragOrigin = useRef<[number, number] | null>(null);
  // Mirrors the selection so the document listeners, registered once per
  // drag, always read the rectangle as it currently stands.
  const currentSelection = useRef<Selection | null>(null);

  // A drag may only start on the graph canvas itself: the wrapper also holds
  // the toolbar, the loading alert and the details bar, which stay clickable.
  const startSelection = (event: ReactMouseEvent) => {
    if (disabled || event.button !== 0) return;
    const canvas = event.target;
    if (!(canvas instanceof HTMLCanvasElement)) return;
    canvasRect.current = canvas.getBoundingClientRect();
    dragOrigin.current = canvasPoint(event, canvasRect.current);
    setIsDragging(true);
  };

  // Tracking happens on the document so that a drag running past the edges of
  // the graph keeps following the cursor and is still applied when the button
  // is released outside.
  useEffect(() => {
    if (!isDragging) return undefined;

    const onMouseMove = (event: MouseEvent) => {
      if (!dragOrigin.current) return;
      const drawn = {
        origin: dragOrigin.current,
        target: canvasPoint(event, canvasRect.current),
        keys: { altKey: event.altKey, shiftKey: event.shiftKey },
      };
      currentSelection.current = drawn;
      setSelection(drawn);
    };

    const onMouseUp = () => {
      const drawn = currentSelection.current;
      if (drawn) onSelection(normalize(drawn), drawn.keys);
      dragOrigin.current = null;
      canvasRect.current = null;
      currentSelection.current = null;
      setSelection(null);
      setIsDragging(false);
    };

    document.addEventListener('mousemove', onMouseMove);
    document.addEventListener('mouseup', onMouseUp);
    return () => {
      document.removeEventListener('mousemove', onMouseMove);
      document.removeEventListener('mouseup', onMouseUp);
    };
  }, [isDragging, onSelection]);

  const rectangle = selection ? normalize(selection) : null;

  const overlayColor = theme.palette.background?.accent
    ? hexToRGB(theme.palette.background.accent, 0.3)
    : theme.palette.warn.main;
  const borderColor = theme.palette.warn.main;

  return (
    <div
      style={{
        position: 'relative',
        height: 'inherit',
        width: 'inherit',
        userSelect: isDragging ? 'none' : undefined,
      }}
      onMouseDown={startSelection}
    >
      {rectangle && (
        <div
          data-testid="rectangle-selection-overlay"
          style={{
            position: 'absolute',
            left: rectangle.origin[0],
            top: rectangle.origin[1],
            width: rectangle.target[0] - rectangle.origin[0],
            height: rectangle.target[1] - rectangle.origin[1],
            backgroundColor: overlayColor,
            border: `1px dashed ${borderColor}`,
            pointerEvents: 'none',
            zIndex: 10,
          }}
        />
      )}
      {children}
    </div>
  );
};

export default RectangleSelection;
