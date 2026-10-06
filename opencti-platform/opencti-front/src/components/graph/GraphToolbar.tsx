import React, { ReactNode, useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState } from 'react';
import { createPortal } from 'react-dom';
import { Paper } from '@filigran/design-system';
import Divider from '@mui/material/Divider';
import { useTheme } from '@mui/material/styles';
import LinearProgress from '@mui/material/LinearProgress';
import Popover from '@mui/material/Popover';
import { PencilPlusOutline } from 'mdi-material-ui';
import useGraphInteractions from './utils/useGraphInteractions';
import SearchInput from '../SearchInput';
import type { Theme } from '../Theme';
import GraphToolbarContentTools, { GraphToolbarContentToolsProps } from './components/GraphToolbarContentTools';
import GraphToolbarTimeRange from './components/GraphToolbarTimeRange';
import { useGraphContext } from './GraphContext';
import { useGraphView } from './GraphViewContext';
import GraphToolbarExpandTools, { GraphToolbarExpandToolsProps } from './components/GraphToolbarExpandTools';
import GraphToolbarItem from './components/GraphToolbarItem';
import GraphToolbarOptionsList from './components/GraphToolbarOptionsList';
import GraphToolbarMoreActions from './components/GraphToolbarMoreActions';
import GraphCounters from './components/GraphCounters';
import useGraphToolbarActions, { type GraphToolbarAction, type GraphToolbarGroup, useGraphToolbarGroupLabels } from './components/useGraphToolbarActions';
import useToolbarRovingFocus from './utils/useToolbarRovingFocus';
import { FOLDED_CREATION_WIDTH, planToolbarOverflow, shouldFoldCreationTools } from './utils/graphToolbarOverflow';
import { useFormatter } from '../i18n';
import useAuth from '../../utils/hooks/useAuth';
import { MESSAGING$ } from '../../relay/environment';
import { OPEN_BAR_WIDTH, SMALL_BAR_WIDTH } from '@components/nav/navBarConstants';
import useDraftContext, { DRAFT_TOOLBAR_HEIGHT } from '../../utils/hooks/useDraftContext';
import useResizeObserver from '../../utils/hooks/useResizeObserver';
import { SURFACE_LAYER, layerInputVars } from '../../utils/fdsLayer';
import { GRAPH_TOOLBAR_HEIGHT, GRAPH_TOOLBAR_HEIGHT_WITH_TIME_RANGE } from './utils/graphFraming';

export type GraphToolbarProps = GraphToolbarContentToolsProps & GraphToolbarExpandToolsProps & {
  /** Called once "Unfix the nodes and re-apply forces" released the saved positions. */
  onUnfixNodes?: () => void;
  warning?: React.ReactNode;
};

/** Gap between two controls of the toolbar, in theme spacing units and in pixels. */
const GAP_UNITS = 0.5;
const GAP_PX = 4;
const SEARCH_WIDTH = 220;

/**
 * Pinned parts never move to the "More actions" menu: their width is measured, the rest is
 * planned. `creation` marks the creation and removal tools, measured apart because they fold.
 */
const Pinned = ({ children, style, label, creation }: { children: ReactNode; style?: React.CSSProperties; label?: string; creation?: boolean }) => (
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

const GroupDivider = () => <Divider orientation="vertical" aria-hidden sx={{ height: 24, marginX: 1, flexShrink: 0 }} />;

/**
 * The one toolbar of a graph, docked under it: the counters of what is drawn, then the actions
 * grouped by intent (view, layout, selection, creation and removal, filters, export, help), the
 * search, and a "More actions" menu for the rare actions and those the toolbar has no room for.
 * It is one tab stop; the arrow keys move between its controls.
 */
const GraphToolbar = ({
  onInvestigationExpand,
  onInvestigationRollback,
  onUnfixNodes,
  warning,
  ...props
}: GraphToolbarProps) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
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
  const { selectBySearch } = useGraphInteractions();
  const view = useGraphView();
  const actions = useGraphToolbarActions({ onUnfixNodes });
  const groupLabels = useGraphToolbarGroupLabels();

  const posBottom = draftContext ? DRAFT_TOOLBAR_HEIGHT : 0;

  const {
    graphState: {
      showTimeRange,
      showLinearProgress,
      loadingCurrent,
      loadingTotal,
      search,
    },
    context,
    isFullscreen,
    toolbarRef,
  } = useGraphContext();

  const editable = context !== 'analyses';

  // --- Room: what the pinned parts leave decides which actions stay in the toolbar. The creation
  // and removal tools are pinned too, but fold into one button when the row cannot hold them.
  const rowRef = useRef<HTMLDivElement | null>(null);
  const { width: rowWidth } = useResizeObserver(rowRef);
  const [fixedWidth, setFixedWidth] = useState(0);
  const [creationWidth, setCreationWidth] = useState(0);
  const [creationFolded, setCreationFolded] = useState(false);
  const [creationAnchor, setCreationAnchor] = useState<HTMLElement | null>(null);
  const padding = parseFloat(theme.spacing(1.5)) * 2;
  const available = rowWidth > 0 ? rowWidth - padding - fixedWidth : Infinity;
  const foldCreation = editable && shouldFoldCreationTools(available, creationWidth, creationFolded);
  useLayoutEffect(() => {
    const row = rowRef.current;
    if (!row) return;
    const widthOf = (selector: string) => Array.from(row.querySelectorAll<HTMLElement>(selector))
      .reduce((sum, element) => sum + element.offsetWidth + GAP_PX, 0);
    const fixed = widthOf(':scope > [data-toolbar-pinned]:not([data-toolbar-creation])');
    if (Math.abs(fixed - fixedWidth) > 1) setFixedWidth(fixed);
    // Measured while in the row; folded, their last width decides when they come back.
    const creation = widthOf(':scope > [data-toolbar-creation]');
    if (!creationFolded && Math.abs(creation - creationWidth) > 1) setCreationWidth(creation);
    if (foldCreation !== creationFolded) {
      setCreationFolded(foldCreation);
      setCreationAnchor(null);
    }
  });
  let creationRoom = 0;
  if (editable) creationRoom = creationFolded ? FOLDED_CREATION_WIDTH : creationWidth;
  const room = available - creationRoom;
  const shownIds = useMemo(() => planToolbarOverflow(actions, room), [actions, room]);
  const shown = (group: GraphToolbarGroup) => actions.filter((action) => action.group === group && shownIds.has(action.id));
  // In a graph view the rare actions (priority 0) are in its context menu: "More actions" holds only what has no room.
  const overflowed = actions.filter((action) => !shownIds.has(action.id) && !(view && action.priority === 0));

  const roving = useToolbarRovingFocus(rowRef);

  // A list (select by type, filters) opens as a menu anchored to its tool.
  const renderAction = (action: GraphToolbarAction) => (
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
  const group = (name: GraphToolbarGroup, first = false) => {
    const items = shown(name);
    if (items.length === 0) return null;
    return (
      <React.Fragment key={name}>
        {!first && <GroupDivider />}
        <div role="group" aria-label={groupLabels[name]} style={{ display: 'flex', alignItems: 'center', gap: GAP_PX, flexShrink: 0 }}>
          {items.map(renderAction)}
        </div>
      </React.Fragment>
    );
  };

  const isLoadingData = (loadingCurrent ?? 0) < (loadingTotal ?? 0);
  // The toolbar starts where the navigation ends; in full screen the graph covers the navigation.
  let navOffset = navOpen ? OPEN_BAR_WIDTH : SMALL_BAR_WIDTH;
  if (isFullscreen) navOffset = 0;
  const hasCounters = !!view && view.counters.length > 0;
  const creationLabel = t_i18n('Creation and removal');
  const creationTools = (
    <>
      {context === 'investigation' && (
        <GraphToolbarExpandTools
          onInvestigationExpand={onInvestigationExpand}
          onInvestigationRollback={onInvestigationRollback}
        />
      )}
      <GraphToolbarContentTools {...props} />
    </>
  );
  // The creation and removal tools are one subtree mounted whatever the room, rendered into one host element that
  // moves between the row and the keep-mounted popover of the folded row: their dialogs (a relationship drawn with the
  // right button included) live in them, so folding or unfolding the row never closes one.
  const creationHost = useMemo(() => {
    const host = document.createElement('div');
    host.setAttribute('data-graph-creation-tools', '');
    host.style.display = 'flex';
    host.style.alignItems = 'center';
    host.style.gap = `${GAP_PX}px`;
    return host;
  }, []);
  const attachCreationHost = useCallback((slot: HTMLDivElement | null) => {
    if (slot && creationHost.parentElement !== slot) slot.appendChild(creationHost);
  }, [creationHost]);

  return (
    // The surface of the legend and the details panel, docked: square, with only its top edge drawn.
    <Paper
      ref={toolbarRef}
      elevation={SURFACE_LAYER}
      padding={0}
      className="rounded-none border-0 border-t"
      data-graph-toolbar=""
      style={{
        ...layerInputVars,
        position: 'fixed',
        left: navOffset,
        right: 'var(--chatbot-sidebar-width, 0px)',
        bottom: posBottom,
        zIndex: 1,
        display: 'flex',
        flexDirection: 'column',
        transition: 'right 225ms cubic-bezier(0.4, 0, 0.2, 1), height 0.2s ease',
        height: showTimeRange ? GRAPH_TOOLBAR_HEIGHT_WITH_TIME_RANGE : GRAPH_TOOLBAR_HEIGHT,
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
          visibility: showLinearProgress || isLoadingData ? 'visible' : 'hidden',
        }}
      />
      <div
        ref={rowRef}
        role="toolbar"
        aria-label={t_i18n('Graph toolbar')}
        aria-orientation="horizontal"
        onKeyDown={roving.onKeyDown}
        onFocus={roving.onFocus}
        style={{
          height: 54,
          flex: '0 0 auto',
          display: 'flex',
          alignItems: 'center',
          gap: theme.spacing(GAP_UNITS),
          padding: `0 ${theme.spacing(1.5)}`,
          overflow: 'hidden',
        }}
      >
        {view && hasCounters && (
          <Pinned><GraphCounters counters={view.counters} /></Pinned>
        )}
        {group('view', !hasCounters)}
        {group('layout')}
        {group('selection')}

        {editable && (
          <>
            <Pinned creation><GroupDivider /></Pinned>
            {creationFolded ? (
              <Pinned creation>
                <GraphToolbarItem
                  title={creationLabel}
                  Icon={<PencilPlusOutline />}
                  pressed={!!creationAnchor}
                  onClick={(event) => setCreationAnchor(event.currentTarget)}
                />
              </Pinned>
            ) : (
              <Pinned creation label={creationLabel}>
                <div ref={attachCreationHost} style={{ display: 'contents' }} />
              </Pinned>
            )}
            {/* In the row, so the keys pressed on an inline tool reach the roving focus of the toolbar. */}
            {createPortal(creationTools, creationHost)}
          </>
        )}

        {group('filters')}
        {warning && (
          <Pinned style={{ flexShrink: 1, minWidth: 0 }}>{warning}</Pinned>
        )}
        {group('export')}
        {group('help')}

        {/* The analyses graph has the search field of its page above it, which filters the containers drawn:
            a second field there, selecting in the graph, would look the same and do something else. */}
        {editable && (
          <Pinned style={{ width: SEARCH_WIDTH, marginLeft: 'auto' }}>
            <div style={{ width: '100%' }} data-graph-search>
              <SearchInput
                keyword={search ?? ''}
                onSubmit={selectBySearch}
              />
            </div>
          </Pinned>
        )}
        <Pinned style={editable ? undefined : { marginLeft: 'auto' }}>
          <GraphToolbarMoreActions actions={overflowed} />
        </Pinned>
      </div>

      {/* Kept mounted while closed: the host of the creation tools lives in it while the row is folded. */}
      {editable && creationFolded && (
        <Popover
          open={!!creationAnchor}
          anchorEl={creationAnchor}
          keepMounted
          onClose={() => setCreationAnchor(null)}
          anchorOrigin={{ vertical: 'top', horizontal: 'center' }}
          transformOrigin={{ vertical: 'bottom', horizontal: 'center' }}
        >
          <div ref={attachCreationHost} role="group" aria-label={creationLabel} style={{ padding: theme.spacing(1) }} />
        </Popover>
      )}

      {/* Only mounted while shown: the closed toolbar clips it, and its handles would stay reachable from the keyboard. */}
      {showTimeRange && <GraphToolbarTimeRange />}
    </Paper>
  );
};

export default GraphToolbar;
