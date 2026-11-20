import React, { useCallback, useMemo, useState } from 'react';
import { createPortal } from 'react-dom';
import { useTheme } from '@mui/material/styles';
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
import GraphCounters from './components/GraphCounters';
import useGraphToolbarActions, { GRAPH_TOOLBAR_GROUPS, type GraphToolbarAction, type GraphToolbarGroup, useGraphToolbarGroupLabels } from './components/useGraphToolbarActions';
import ToolbarShell, { GroupDivider, type ToolbarSlot } from './ToolbarShell';
import { useFormatter } from '../i18n';
import { GRAPH_TOOLBAR_HEIGHT, GRAPH_TOOLBAR_HEIGHT_WITH_TIME_RANGE } from './utils/graphFraming';

export type GraphToolbarProps = GraphToolbarContentToolsProps & GraphToolbarExpandToolsProps & {
  /** Called once "Unfix the nodes and re-apply forces" released the saved positions. */
  onUnfixNodes?: () => void;
  warning?: React.ReactNode;
};

const GAP_PX = 4;
const SEARCH_WIDTH = 220;

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
  const { selectBySearch } = useGraphInteractions();
  const view = useGraphView();
  const actions = useGraphToolbarActions({ onUnfixNodes });
  const groupLabels = useGraphToolbarGroupLabels();

  const {
    graphState: {
      mode3D,
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
  const [creationAnchor, setCreationAnchor] = useState<HTMLElement | null>(null);

  // In a 2D graph view the rare actions (priority 0) are in its context menu: "More actions" holds only what has no room.
  // The 3D canvas has no context menu: "More actions" holds them there, with the other actions of its selection and
  // of its empty canvas.
  const inContextMenu = (action: GraphToolbarAction) => !!view && !mode3D && action.priority === 0;
  const menuOnly = mode3D ? [...(view?.selectionActions ?? []), ...(view?.canvasActions ?? [])] : [];

  const isLoadingData = (loadingCurrent ?? 0) < (loadingTotal ?? 0);
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
      <GraphToolbarContentTools
        {...props}
        onInvestigationExpand={onInvestigationExpand}
      />
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

  const layout: ToolbarSlot<GraphToolbarGroup>[] = [
    ...(view && hasCounters ? [{ kind: 'pinned' as const, key: 'counters', render: () => <GraphCounters counters={view.counters} /> }] : []),
    { kind: 'group', group: 'view' },
    { kind: 'group', group: 'layout' },
    { kind: 'group', group: 'selection' },
    ...(editable ? [
      { kind: 'pinned' as const, key: 'creation-divider', foldable: true, render: () => <GroupDivider /> },
      {
        kind: 'pinned' as const,
        key: 'creation',
        foldable: true,
        label: ({ folded }: { folded: boolean }) => (folded ? undefined : creationLabel),
        // The portal stays the second child whether folded or not: the tools are never remounted.
        render: ({ folded }: { folded: boolean }) => (
          <>
            {folded ? (
              <GraphToolbarItem
                title={creationLabel}
                Icon={<PencilPlusOutline />}
                pressed={!!creationAnchor}
                onClick={(event) => setCreationAnchor(event.currentTarget)}
              />
            ) : (
              <div ref={attachCreationHost} style={{ display: 'contents' }} />
            )}
            {/* In the row, so the keys pressed on an inline tool reach the roving focus of the toolbar. */}
            {createPortal(creationTools, creationHost)}
          </>
        ),
      },
    ] : []),
    { kind: 'group', group: 'filters' },
    ...(warning ? [{ kind: 'pinned' as const, key: 'warning', style: { flexShrink: 1, minWidth: 0 }, render: () => warning }] : []),
    { kind: 'group', group: 'export' },
    { kind: 'group', group: 'help' },
    // The analyses graph has the search field of its page above it, which filters the containers drawn:
    // a second field there, selecting in the graph, would look the same and do something else.
    ...(editable ? [{
      kind: 'pinned' as const,
      key: 'search',
      style: { width: SEARCH_WIDTH, marginLeft: 'auto' },
      render: () => (
        <div style={{ width: '100%' }} data-graph-search>
          <SearchInput
            keyword={search ?? ''}
            onSubmit={selectBySearch}
          />
        </div>
      ),
    }] : []),
  ];

  return (
    <ToolbarShell<GraphToolbarGroup>
      label={t_i18n('Graph toolbar')}
      layout={layout}
      actions={actions}
      groups={GRAPH_TOOLBAR_GROUPS}
      groupLabels={groupLabels}
      menuOnly={menuOnly}
      listInMoreActions={(action) => !inContextMenu(action)}
      pushMoreActionsRight={!editable}
      height={showTimeRange ? GRAPH_TOOLBAR_HEIGHT_WITH_TIME_RANGE : GRAPH_TOOLBAR_HEIGHT}
      progress={showLinearProgress || isLoadingData}
      fullscreen={isFullscreen}
      paperRef={toolbarRef}
      rootAttributes={{ 'data-graph-toolbar': '' }}
      onFoldChange={() => setCreationAnchor(null)}
      // Kept mounted while closed: the host of the creation tools lives in it while the row is folded.
      renderAfterRow={({ folded }) => editable && folded && (
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
      // Only mounted while shown: the closed toolbar clips it, and its handles would stay reachable from the keyboard.
      below={showTimeRange && <GraphToolbarTimeRange />}
    />
  );
};

export default GraphToolbar;
