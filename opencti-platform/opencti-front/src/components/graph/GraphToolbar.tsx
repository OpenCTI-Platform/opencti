import React, { ReactNode, useLayoutEffect, useMemo, useRef, useState } from 'react';
import { Paper } from '@filigran/design-system';
import Divider from '@mui/material/Divider';
import { useTheme } from '@mui/material/styles';
import LinearProgress from '@mui/material/LinearProgress';
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
import { planToolbarOverflow } from './utils/graphToolbarOverflow';
import { useFormatter } from '../i18n';
import useAuth from '../../utils/hooks/useAuth';
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

/** Pinned parts never move to the "More actions" menu: their width is measured, the rest is planned. */
const Pinned = ({ children, style, label }: { children: ReactNode; style?: React.CSSProperties; label?: string }) => (
  <div
    data-toolbar-pinned=""
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
  const navOpen = localStorage.getItem('navOpen') === 'true';
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

  // --- Room: what the pinned parts leave decides which actions stay in the toolbar.
  const rowRef = useRef<HTMLDivElement | null>(null);
  const { width: rowWidth } = useResizeObserver(rowRef);
  const [pinnedWidth, setPinnedWidth] = useState(0);
  useLayoutEffect(() => {
    const row = rowRef.current;
    if (!row) return;
    const pinned = Array.from(row.querySelectorAll<HTMLElement>(':scope > [data-toolbar-pinned]'));
    const total = pinned.reduce((sum, element) => sum + element.offsetWidth + GAP_PX, 0);
    if (Math.abs(total - pinnedWidth) > 1) setPinnedWidth(total);
  });
  const padding = parseFloat(theme.spacing(1.5)) * 2;
  const room = rowWidth > 0 ? rowWidth - padding - pinnedWidth : Infinity;
  const shownIds = useMemo(() => planToolbarOverflow(actions, room), [actions, room]);
  const shown = (group: GraphToolbarGroup) => actions.filter((action) => action.group === group && shownIds.has(action.id));
  const overflowed = actions.filter((action) => !shownIds.has(action.id));

  const roving = useToolbarRovingFocus(rowRef);

  // --- Lists opened from the toolbar (select by type, filters).
  const [openList, setOpenList] = useState<{ id: string; anchor: Element }>();
  const listAction = openList ? actions.find((action) => action.id === openList.id) : undefined;
  const renderAction = (action: GraphToolbarAction) => (
    <GraphToolbarItem
      key={action.id}
      title={action.label}
      Icon={action.icon}
      shortcut={action.shortcut}
      pressed={action.pressed}
      disabledReason={action.disabledReason}
      badge={action.badge}
      onClick={(event) => {
        if (action.options) setOpenList({ id: action.id, anchor: event.currentTarget });
        else action.onSelect?.();
      }}
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
  const editable = context !== 'analyses';
  const hasCounters = !!view && view.counters.length > 0;

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
            <GroupDivider />
            <Pinned label={t_i18n('Creation and removal')}>
              {context === 'investigation' && (
                <GraphToolbarExpandTools
                  onInvestigationExpand={onInvestigationExpand}
                  onInvestigationRollback={onInvestigationRollback}
                />
              )}
              <GraphToolbarContentTools {...props} />
            </Pinned>
          </>
        )}

        {group('filters')}
        {warning && (
          <Pinned style={{ flexShrink: 1, minWidth: 0 }}>{warning}</Pinned>
        )}
        {group('export')}
        {group('help')}

        {editable && (
          <Pinned style={{ width: SEARCH_WIDTH, marginLeft: 'auto' }}>
            <div style={{ width: '100%' }} data-graph-search>
              <SearchInput
                keyword={search ?? ''}
                variant="thin"
                onSubmit={selectBySearch}
              />
            </div>
          </Pinned>
        )}
        <Pinned style={editable ? undefined : { marginLeft: 'auto' }}>
          <GraphToolbarMoreActions actions={overflowed} />
        </Pinned>
      </div>

      {listAction?.options && openList && (
        <GraphToolbarOptionsList
          isMultiple={listAction.options.multiple}
          anchorEl={openList.anchor}
          onClose={() => setOpenList(undefined)}
          options={listAction.options.items}
          getOptionKey={(option) => option.key}
          getOptionText={(option) => option.label}
          getOptionSection={(option) => option.section}
          isOptionSelected={(option) => !!option.selected}
          onSelect={(option) => {
            listAction.options?.onSelect(option.key);
            if (!listAction.options?.multiple) setOpenList(undefined);
          }}
        />
      )}

      {/* Only mounted while shown: the closed toolbar clips it, and its handles would stay reachable from the keyboard. */}
      {showTimeRange && <GraphToolbarTimeRange />}
    </Paper>
  );
};

export default GraphToolbar;
