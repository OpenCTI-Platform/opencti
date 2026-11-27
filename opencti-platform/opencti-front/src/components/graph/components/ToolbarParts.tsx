import React, { CSSProperties, ReactNode } from 'react';
import Divider from '@mui/material/Divider';
import { TOOLBAR_GAP_PX } from '../utils/graphToolbarOverflow';

/**
 * Data attributes the toolbar measures (see `useToolbarRoom`).
 * The parts below write them; the selectors read them. Keep both here.
 */
export const PINNED_SELECTOR = ':scope > [data-toolbar-pinned]:not([data-toolbar-creation])';
export const CREATION_SELECTOR = ':scope > [data-toolbar-creation]';
export const WIDE_CONTROL_SELECTOR = '[data-toolbar-action]';
export const WIDE_CONTROL_ID_ATTRIBUTE = 'data-toolbar-action';

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

/** A wide control (a select, a combobox) in the row. Measured by its id, and watched for size changes through `observe`. */
export const WideControl = ({ id, render, observe }: {
  id: string;
  render: () => ReactNode;
  observe: (element: HTMLDivElement | null) => (() => void) | undefined;
}) => (
  <div ref={observe} data-toolbar-action={id} style={{ display: 'flex', alignItems: 'center', flexShrink: 0 }}>
    <RenderFunction render={render} />
  </div>
);

export const GroupDivider = () => <Divider orientation="vertical" aria-hidden sx={{ height: 24, marginX: 1, flexShrink: 0 }} />;
