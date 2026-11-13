import { Handle, Position } from 'reactflow';
import type { LayoutDirection } from '../layout/LayoutEngine';

export const NodeHandles = ({ direction }: { direction: LayoutDirection }) => (
  <>
    <Handle type="target" position={direction === 'TB' ? Position.Top : Position.Left} isConnectable={false} className="sv-handle" />
    <Handle type="source" position={direction === 'TB' ? Position.Bottom : Position.Right} isConnectable={false} className="sv-handle" />
  </>
);
