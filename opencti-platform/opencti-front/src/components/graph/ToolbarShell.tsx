import React, { CSSProperties, ReactNode, Ref, useMemo, useRef } from 'react';
import { Paper } from '@filigran/design-system';
import { useTheme } from '@mui/material/styles';
import LinearProgress from '@mui/material/LinearProgress';
import type { Theme } from '../Theme';
import GraphToolbarMoreActions from './components/GraphToolbarMoreActions';
import ToolbarSlots from './components/ToolbarSlots';
import { Pinned } from './components/ToolbarParts';
import type { GraphToolbarOption } from './components/useGraphToolbarActions';
import useToolbarRovingFocus from './utils/useToolbarRovingFocus';
import useToolbarRoom from './utils/useToolbarRoom';
import useDockedToolbarPosition from './utils/useDockedToolbarPosition';
import { planToolbarOverflow, TOOLBAR_GAP_UNITS, type ToolbarOverflowCandidate } from './utils/graphToolbarOverflow';
import { SURFACE_LAYER, layerInputVars } from '../../utils/fdsLayer';

export interface ToolbarAction<G extends string = string> extends ToolbarOverflowCandidate {
  group: G;
  /** Translated, sentence case. Stays the same when a toggle changes state. */
  label: string;
  icon: ReactNode;
  shortcut?: string;
  /** What the action does, shown under its name in the tooltip while it is available. */
  description?: string;
  /** For a toggle: whether it is on. */
  pressed?: boolean;
  /** Set when the action is not available now. Says why. */
  disabledReason?: string;
  /** Number of filters or choices in use. */
  badge?: number;
  onSelect?: () => void;
  /** A list to choose from. Opens as a menu from the row, as a submenu from "More actions". */
  options?: {
    items: GraphToolbarOption[];
    multiple?: boolean;
    onSelect: (key: string) => void;
  };
  /**
   * A wide control (a select, a combobox) drawn instead of an icon button. Measured once drawn; `width` is the estimate until then.
   * The control unmounts when it moves to "More actions": keep its value in the caller's state, not in the control.
   */
  render?: () => ReactNode;
  /** What "More actions" shows for this control when the row has no room for it. Default: `render`. */
  submenu?: () => ReactNode;
}

export type ToolbarSlot<G extends string> =
  | { kind: 'group'; group: G }
  | {
    kind: 'pinned';
    key: string;
    label?: string | ((state: { folded: boolean }) => string | undefined);
    style?: CSSProperties;
    /** Folds into one button, with the other foldable slots, when the row cannot hold them (the graph creation tools). */
    foldable?: boolean;
    render: (state: { folded: boolean }) => ReactNode;
  };

export interface ToolbarShellProps<G extends string> {
  label: string;
  /** Slots from left to right. A group slot gets a divider before it, unless it is the first drawn. */
  layout: readonly ToolbarSlot<G>[];
  actions: readonly ToolbarAction<G>[];
  groups: readonly G[];
  groupLabels: Record<G, string>;
  /** Actions listed only in "More actions", never in the row. */
  menuOnly?: readonly ToolbarAction<G>[];
  /** Whether an action without room in the row is listed in "More actions". Default: yes. */
  listInMoreActions?: (action: ToolbarAction<G>) => boolean;
  pushMoreActionsRight?: boolean;
  height: number;
  progress?: boolean;
  fullscreen?: boolean;
  paperRef?: Ref<HTMLDivElement>;
  rootAttributes?: Record<`data-${string}`, string>;
  /** Drawn under the row (the graph time range). */
  below?: ReactNode;
  /** Drawn after the row, outside its keyboard path (the popover of the folded creation tools). */
  renderAfterRow?: (state: { folded: boolean }) => ReactNode;
  onFoldChange?: (folded: boolean) => void;
}

const ROW_HEIGHT = 54;
const ROW_PADDING_UNITS = 1.5;

/**
 * The toolbar docked under a view, shared by the graph and the matrix.
 *
 * 1. `useToolbarRoom` measures the row and returns the room left for the actions.
 * 2. `planToolbarOverflow` picks the actions that fit in that room.
 * 3. `ToolbarSlots` draws them; the others go to "More actions".
 */
const ToolbarShell = <G extends string>({
  label,
  layout,
  actions,
  groups,
  groupLabels,
  menuOnly = [],
  listInMoreActions,
  pushMoreActionsRight,
  height,
  progress,
  fullscreen,
  paperRef,
  rootAttributes,
  below,
  renderAfterRow,
  onFoldChange,
}: ToolbarShellProps<G>) => {
  const theme = useTheme<Theme>();
  const position = useDockedToolbarPosition(fullscreen);
  const rowRef = useRef<HTMLDivElement | null>(null);
  const roving = useToolbarRovingFocus(rowRef);

  const { room, folded, wideWidths, observeWide } = useToolbarRoom(rowRef, {
    padding: parseFloat(theme.spacing(ROW_PADDING_UNITS)) * 2,
    hasFoldable: layout.some((slot) => slot.kind === 'pinned' && slot.foldable),
    onFoldChange,
  });

  // A wide control is planned with its measured width, once it has one.
  const shownIds = useMemo(
    () => planToolbarOverflow(actions.map((action) => (action.render ? { ...action, width: wideWidths[action.id] ?? action.width } : action)), room),
    [actions, room, wideWidths],
  );
  const overflowed = [
    ...actions.filter((action) => !shownIds.has(action.id) && (listInMoreActions?.(action) ?? true)),
    ...menuOnly,
  ];

  return (
    // Same surface as the legend and the details panel, docked: square corners, only the top border.
    <Paper
      ref={paperRef}
      elevation={SURFACE_LAYER}
      padding={0}
      className="rounded-none border-0 border-t"
      {...rootAttributes}
      style={{
        ...layerInputVars,
        ...position,
        position: 'fixed',
        zIndex: 1,
        display: 'flex',
        flexDirection: 'column',
        transition: 'right 225ms cubic-bezier(0.4, 0, 0.2, 1), height 0.2s ease',
        height,
        overflow: 'hidden',
      }}
    >
      <LinearProgress
        style={{
          width: '100%',
          height: 2,
          position: 'absolute',
          top: -1,
          visibility: progress ? 'visible' : 'hidden',
        }}
      />
      <div
        ref={rowRef}
        role="toolbar"
        aria-label={label}
        aria-orientation="horizontal"
        onKeyDown={roving.onKeyDown}
        onFocus={roving.onFocus}
        style={{
          height: ROW_HEIGHT,
          flex: '0 0 auto',
          display: 'flex',
          alignItems: 'center',
          gap: theme.spacing(TOOLBAR_GAP_UNITS),
          padding: `0 ${theme.spacing(ROW_PADDING_UNITS)}`,
          overflow: 'hidden',
        }}
      >
        <ToolbarSlots
          layout={layout}
          actions={actions}
          shownIds={shownIds}
          groupLabels={groupLabels}
          folded={folded}
          observeWide={observeWide}
        />
        {/* Drawn only when it has content: an empty item would still take a gap and stop the last control short of the right edge. */}
        {overflowed.length > 0 && (
          <Pinned style={pushMoreActionsRight ? { marginLeft: 'auto' } : undefined}>
            <GraphToolbarMoreActions actions={overflowed} groups={groups} groupLabels={groupLabels} />
          </Pinned>
        )}
      </div>
      {renderAfterRow?.({ folded })}
      {below}
    </Paper>
  );
};

export default ToolbarShell;
