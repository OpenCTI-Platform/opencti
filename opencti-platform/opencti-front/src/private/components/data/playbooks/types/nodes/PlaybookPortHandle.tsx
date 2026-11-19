import React from 'react';
import { Handle, Position, type XYPosition } from 'reactflow';
import type { PlaybookLayoutDirection } from '../../hooks/usePlaybookLayoutMode';
import { PLAYBOOK_PORT_PILL_MAX_WIDTH } from './playbookNodeGeometry';
import PlaybookHandleHint from './PlaybookHandleHint';

interface PlaybookPortHandleProps {
  portId: string;
  portName: string;
  nodeId: string;
  position: Position;
  anchor: XYPosition;
  direction: PlaybookLayoutDirection;
  accent: string;
  textColor?: string;
  background?: string;
  isConnectable: boolean;
  opensSettings: boolean;
  onOpen: () => void;
  // What a drag from this output does (edit mode only).
  hint?: string;
}

// The source handle of a labelled port IS its pill: the box, the border and the name are the handle's
// own, so a pointer down anywhere on the pill starts React Flow's connection (it reads the element under
// the pointer and needs the handle itself, which is why the name is a bare text node and never a child
// element), and a hover anywhere on it reads the full name. A click without a drag opens the step's
// configuration like a click on the card; the keyboard path is the card's title button.
const PlaybookPortHandle = ({
  portId,
  portName,
  nodeId,
  position,
  anchor,
  direction,
  accent,
  textColor,
  background,
  isConnectable,
  opensSettings,
  onOpen,
  hint,
}: PlaybookPortHandleProps) => (
  <PlaybookHandleHint side={position} hint={hint}>
    <Handle
      id={portId}
      type="source"
      position={position}
      isConnectable={isConnectable}
      isConnectableStart={isConnectable}
      className="playbook-port-pill"
      data-testid={`playbook-port-${nodeId}-${portId}`}
      title={hint ? undefined : portName}
      onClick={(event) => {
        event.stopPropagation();
        onOpen();
      }}
      style={{
        // Centred on the port anchor of the card edge, whatever side React Flow puts the handle on.
        left: anchor.x,
        top: anchor.y,
        right: 'auto',
        bottom: 'auto',
        transform: 'translate(-50%, -50%)',
        zIndex: 1,
        width: 'auto',
        height: 'auto',
        minWidth: 0,
        minHeight: 0,
        boxSizing: 'border-box',
        padding: '1px 8px',
        borderRadius: 10,
        fontSize: 10,
        lineHeight: '16px',
        whiteSpace: 'nowrap',
        ...(direction === 'horizontal' && {
          maxWidth: PLAYBOOK_PORT_PILL_MAX_WIDTH,
          overflow: 'hidden',
          textOverflow: 'ellipsis',
        }),
        color: textColor,
        backgroundColor: background,
        border: `1px solid ${accent}`,
        ['--playbook-port-accent' as string]: accent,
        // React Flow lets pointer events through a handle that cannot connect (view mode): the pill still
        // answers the hover so its full name is read.
        pointerEvents: 'all',
        cursor: isConnectable ? 'crosshair' : (opensSettings ? 'pointer' : 'default'),
      }}
    >
      {portName}
    </Handle>
  </PlaybookHandleHint>
);

export default PlaybookPortHandle;
