import React, { CSSProperties, ReactNode } from 'react';
import Divider from '@mui/material/Divider';
import { TOOLBAR_GAP_PX } from '../utils/graphToolbarOverflow';

/**
 * A part of the toolbar row that never moves to "More actions".
 * The toolbar measures pinned parts to know how much room is left for the actions.
 * `creation` marks the parts that can fold into one button (the graph creation tools).
 * They are measured separately, because they fold.
 */
export const Pinned = ({ children, style, label, creation }: { children: ReactNode; style?: CSSProperties; label?: string; creation?: boolean }) => (
  <div
    data-toolbar-pinned=""
    data-toolbar-creation={creation ? '' : undefined}
    role={label ? 'group' : undefined}
    aria-label={label}
    style={{ display: 'flex', alignItems: 'center', gap: TOOLBAR_GAP_PX, flexShrink: 0, ...style }}
  >
    {children}
  </div>
);

/**
 * Calls a render function as its own component.
 * This keeps the hooks of the render function working when its control moves between the row and "More actions".
 */
export const RenderFunction = ({ render }: { render: () => ReactNode }) => <>{render()}</>;

/** Same as `RenderFunction`, for a pinned slot that needs to know whether the creation tools are folded. */
export const RenderSlot = ({ render, folded }: { render: (state: { folded: boolean }) => ReactNode; folded: boolean }) => <>{render({ folded })}</>;

export const GroupDivider = () => <Divider orientation="vertical" aria-hidden sx={{ height: 24, marginX: 1, flexShrink: 0 }} />;
