import React, { CSSProperties, Fragment, ReactNode, Ref, useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState } from 'react';
import { Paper } from '@filigran/design-system';
import Divider from '@mui/material/Divider';
import { useTheme } from '@mui/material/styles';
import LinearProgress from '@mui/material/LinearProgress';
import type { Theme } from '../Theme';
import GraphToolbarItem from './components/GraphToolbarItem';
import GraphToolbarOptionsList from './components/GraphToolbarOptionsList';
import GraphToolbarMoreActions from './components/GraphToolbarMoreActions';
import type { GraphToolbarOption } from './components/useGraphToolbarActions';
import useToolbarRovingFocus from './utils/useToolbarRovingFocus';
import { FOLDED_CREATION_WIDTH, planToolbarOverflow, shouldFoldCreationTools, type ToolbarOverflowCandidate } from './utils/graphToolbarOverflow';
import useAuth from '../../utils/hooks/useAuth';
import { MESSAGING$ } from '../../relay/environment';
import { OPEN_BAR_WIDTH, SMALL_BAR_WIDTH } from '@components/nav/navBarConstants';
import useDraftContext, { DRAFT_TOOLBAR_HEIGHT } from '../../utils/hooks/useDraftContext';
import useResizeObserver from '../../utils/hooks/useResizeObserver';
import { SURFACE_LAYER, layerInputVars } from '../../utils/fdsLayer';

export interface ToolbarAction<G extends string = string> extends ToolbarOverflowCandidate {
  group: G;
  /** Translated, sentence case; the same whatever the state of a toggle. */
  label: string;
  icon: ReactNode;
  shortcut?: string;
  /** Set for a toggle: whether it is on. */
  pressed?: boolean;
  /** Set when the action is not available now, saying why. */
  disabledReason?: string;
  /** Number of filters or choices in use. */
  badge?: number;
  onSelect?: () => void;
  /** A list to choose from: a menu from the toolbar, a submenu from "More actions". */
  options?: {
    items: GraphToolbarOption[];
    multiple?: boolean;
    onSelect: (key: string) => void;
  };
  /** A wide control (a select, a combobox) drawn instead of an icon. Measured; `width` is its estimate until then. */
  render?: () => ReactNode;
  /** What "More actions" shows for this control when the row has no room for it. */
  submenu?: () => ReactNode;
}

export type ToolbarSlot<G extends string> =
  | { kind: 'group'; group: G }
  | {
    kind: 'pinned';
    key: string;
    label?: string | ((state: { folded: boolean }) => string | undefined);
    style?: CSSProperties;
    /** Folds with the other foldable slots when the row cannot hold them (the graph's creation tools). */
    foldable?: boolean;
    render: (state: { folded: boolean }) => ReactNode;
  };

export interface ToolbarShellProps<G extends string> {
  label: string;
  /** Left to right. A group slot draws a divider before it unless nothing is drawn before it. */
  layout: readonly ToolbarSlot<G>[];
  actions: readonly ToolbarAction<G>[];
  groups: readonly G[];
  groupLabels: Record<G, string>;
  menuOnly?: readonly ToolbarAction<G>[];
  listInMoreActions?: (action: ToolbarAction<G>) => boolean;
  pushMoreActionsRight?: boolean;
  height: number;
  progress?: boolean;
  fullscreen?: boolean;
  paperRef?: Ref<HTMLDivElement>;
  rootAttributes?: Record<`data-${string}`, string>;
  below?: ReactNode;
  /** After the row, outside its keyboard path (the folded creation tools' popover). */
  renderAfterRow?: (state: { folded: boolean }) => ReactNode;
  onFoldChange?: (folded: boolean) => void;
}

const GAP_UNITS = 0.5;
const GAP_PX = 4;
const ROW_HEIGHT = 54;

/**
 * Pinned parts never move to the "More actions" menu: their width is measured, the rest is
 * planned. `creation` marks the foldable parts, measured apart because they fold.
 */
export const Pinned = ({ children, style, label, creation }: { children: ReactNode; style?: CSSProperties; label?: string; creation?: boolean }) => (
  <div
    data-toolbar-pinned=""
    data-toolbar-creation={creation ? '' : undefined}
    role={label ? 'group' : undefined}
    aria-label={label}
    style={{ display: 'flex', alignItems: 'center', gap: GAP_PX, flexShrink: 0, ...style }}
  >
    {children}
  </div>
);

// A component of its own, so the hooks of a render function survive a move between the row and "More actions".
export const RenderFunction = ({ render }: { render: () => ReactNode }) => <>{render()}</>;

const RenderSlot = ({ render, folded }: { render: (state: { folded: boolean }) => ReactNode; folded: boolean }) => <>{render({ folded })}</>;

export const GroupDivider = () => <Divider orientation="vertical" aria-hidden sx={{ height: 24, marginX: 1, flexShrink: 0 }} />;

/** The toolbar docked under a view, shared by the graph and the matrix: the actions without room go to "More actions". */
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
  const draftContext = useDraftContext();
  const { bannerSettings: { bannerHeightNumber } } = useAuth();
  // Docked to the left of the window, the toolbar follows the navigation as it opens and closes.
  const [navOpen, setNavOpen] = useState(localStorage.getItem('navOpen') === 'true');
  useEffect(() => {
    const sub = MESSAGING$.toggleNav.subscribe({
      next: () => setNavOpen(localStorage.getItem('navOpen') === 'true'),
    });
    return () => sub.unsubscribe();
  }, []);

  // --- Room: what the pinned parts leave decides which actions stay in the toolbar. The foldable
  // parts are pinned too, but fold into one button when the row cannot hold them.
  const rowRef = useRef<HTMLDivElement | null>(null);
  const { width: rowWidth } = useResizeObserver(rowRef);
  const [fixedWidth, setFixedWidth] = useState(0);
  const [foldableWidth, setFoldableWidth] = useState(0);
  const [folded, setFolded] = useState(false);
  // Width of each wide control, measured while in the row; kept while it waits in "More actions".
  const [wideWidths, setWideWidths] = useState<Record<string, number>>({});
  // A wide control can grow on its own (a chip added): observed, so the row is planned again.
  const [, setResized] = useState(0);
  const wideObserver = useMemo(
    () => (typeof ResizeObserver === 'undefined' ? null : new ResizeObserver(() => setResized((count) => count + 1))),
    [],
  );
  useEffect(() => () => wideObserver?.disconnect(), [wideObserver]);
  const observeWide = useCallback((element: HTMLDivElement | null) => {
    if (!element || !wideObserver) return undefined;
    wideObserver.observe(element);
    return () => wideObserver.unobserve(element);
  }, [wideObserver]);
  const hasFoldable = layout.some((slot) => slot.kind === 'pinned' && slot.foldable);
  const padding = parseFloat(theme.spacing(1.5)) * 2;
  const available = rowWidth > 0 ? rowWidth - padding - fixedWidth : Infinity;
  const foldNow = hasFoldable && shouldFoldCreationTools(available, foldableWidth, folded);
  useLayoutEffect(() => {
    const row = rowRef.current;
    if (!row) return;
    const widthOf = (selector: string) => Array.from(row.querySelectorAll<HTMLElement>(selector))
      .reduce((sum, element) => sum + element.offsetWidth + GAP_PX, 0);
    const fixed = widthOf(':scope > [data-toolbar-pinned]:not([data-toolbar-creation])');
    if (Math.abs(fixed - fixedWidth) > 1) setFixedWidth(fixed);
    // Measured while in the row; folded, their last width decides when they come back.
    const foldable = widthOf(':scope > [data-toolbar-creation]');
    if (!folded && Math.abs(foldable - foldableWidth) > 1) setFoldableWidth(foldable);
    if (foldNow !== folded) {
      setFolded(foldNow);
      onFoldChange?.(foldNow);
    }
    const changed: Record<string, number> = {};
    row.querySelectorAll<HTMLElement>('[data-toolbar-action]').forEach((element) => {
      const id = element.getAttribute('data-toolbar-action') ?? '';
      const width = element.offsetWidth + GAP_PX;
      if (Math.abs(width - (wideWidths[id] ?? -Infinity)) > 1) changed[id] = width;
    });
    if (Object.keys(changed).length > 0) setWideWidths((current) => ({ ...current, ...changed }));
  });
  let foldRoom = 0;
  if (hasFoldable) foldRoom = folded ? FOLDED_CREATION_WIDTH : foldableWidth;
  const room = available - foldRoom;
  const shownIds = useMemo(
    () => planToolbarOverflow(actions.map((action) => (action.render ? { ...action, width: wideWidths[action.id] ?? action.width } : action)), room),
    [actions, room, wideWidths],
  );
  const overflowed = [
    ...actions.filter((action) => !shownIds.has(action.id) && (listInMoreActions?.(action) ?? true)),
    ...menuOnly,
  ];

  const roving = useToolbarRovingFocus(rowRef);

  // A list (select by type, filters) opens as a menu anchored to its tool.
  const renderAction = (action: ToolbarAction<G>) => {
    if (action.render) {
      return (
        <div key={action.id} ref={observeWide} data-toolbar-action={action.id} style={{ display: 'flex', alignItems: 'center', flexShrink: 0 }}>
          <RenderFunction render={action.render} />
        </div>
      );
    }
    return (
      <GraphToolbarItem
        key={action.id}
        title={action.label}
        Icon={action.icon}
        shortcut={action.shortcut}
        pressed={action.pressed}
        disabledReason={action.disabledReason}
        badge={action.badge}
        menu={action.options ? <GraphToolbarOptionsList options={action.options} /> : undefined}
        onClick={action.options ? undefined : () => action.onSelect?.()}
      />
    );
  };

  let drawn = false;
  const slots = layout.map((slot) => {
    if (slot.kind === 'group') {
      const items = actions.filter((action) => action.group === slot.group && shownIds.has(action.id));
      if (items.length === 0) return null;
      const divided = drawn;
      drawn = true;
      return (
        <Fragment key={`group-${slot.group}`}>
          {divided && <GroupDivider />}
          <div role="group" aria-label={groupLabels[slot.group]} style={{ display: 'flex', alignItems: 'center', gap: GAP_PX, flexShrink: 0 }}>
            {items.map(renderAction)}
          </div>
        </Fragment>
      );
    }
    drawn = true;
    const slotLabel = typeof slot.label === 'function' ? slot.label({ folded }) : slot.label;
    return (
      <Pinned key={`pinned-${slot.key}`} creation={slot.foldable} label={slotLabel} style={slot.style}>
        <RenderSlot render={slot.render} folded={folded} />
      </Pinned>
    );
  });

  // The toolbar starts where the navigation ends; in full screen the view covers the navigation.
  let navOffset = navOpen ? OPEN_BAR_WIDTH : SMALL_BAR_WIDTH;
  if (fullscreen) navOffset = 0;

  return (
    // The surface of the legend and the details panel, docked: square, with only its top edge drawn.
    <Paper
      ref={paperRef}
      elevation={SURFACE_LAYER}
      padding={0}
      className="rounded-none border-0 border-t"
      {...rootAttributes}
      style={{
        ...layerInputVars,
        position: 'fixed',
        left: navOffset,
        right: 'var(--chatbot-sidebar-width, 0px)',
        bottom: draftContext ? DRAFT_TOOLBAR_HEIGHT : 0,
        zIndex: 1,
        display: 'flex',
        flexDirection: 'column',
        transition: 'right 225ms cubic-bezier(0.4, 0, 0.2, 1), height 0.2s ease',
        height,
        overflow: 'hidden',
        marginBottom: bannerHeightNumber,
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
          gap: theme.spacing(GAP_UNITS),
          padding: `0 ${theme.spacing(1.5)}`,
          overflow: 'hidden',
        }}
      >
        {slots}
        {/* An empty item would still take a gap of the row and stop the last control short of its right edge. */}
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
