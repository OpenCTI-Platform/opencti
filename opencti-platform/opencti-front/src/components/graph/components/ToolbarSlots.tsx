import React, { Fragment, ReactNode } from 'react';
import GraphToolbarItem from './GraphToolbarItem';
import GraphToolbarOptionsList from './GraphToolbarOptionsList';
import { GroupDivider, Pinned, WideControl } from './ToolbarParts';
import { TOOLBAR_GAP_PX } from '../utils/graphToolbarOverflow';
import type { ToolbarAction, ToolbarSlot } from '../ToolbarShell';

/** Calls the render function of a pinned slot as its own component, like `RenderFunction`, with the fold state. */
const RenderSlot = ({ render, folded }: { render: (state: { folded: boolean }) => ReactNode; folded: boolean }) => <>{render({ folded })}</>;

interface ToolbarSlotsProps<G extends string> {
  layout: readonly ToolbarSlot<G>[];
  actions: readonly ToolbarAction<G>[];
  /** Ids of the actions that stay in the row. The others are in "More actions". */
  shownIds: Set<string>;
  groupLabels: Record<G, string>;
  folded: boolean;
  /** Ref callback that watches a wide control for size changes. */
  observeWide: (element: HTMLDivElement | null) => (() => void) | undefined;
}

/**
 * The content of the toolbar row, left to right, as the layout orders it.
 * - A group slot draws its shown actions, after a divider. It draws nothing when none of its actions is shown.
 * - A pinned slot is always drawn.
 * The first drawn slot gets no divider before it.
 */
const ToolbarSlots = <G extends string>({ layout, actions, shownIds, groupLabels, folded, observeWide }: ToolbarSlotsProps<G>) => {
  const renderAction = (action: ToolbarAction<G>) => {
    // A wide control (a select, a combobox) is drawn as is, and measured.
    if (action.render) {
      return <WideControl key={action.id} id={action.id} render={action.render} observe={observeWide} />;
    }
    // An action with options opens them as a menu anchored to its button.
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

  let somethingDrawn = false;
  const slots = layout.map((slot) => {
    if (slot.kind === 'group') {
      const items = actions.filter((action) => action.group === slot.group && shownIds.has(action.id));
      if (items.length === 0) return null;
      const withDivider = somethingDrawn;
      somethingDrawn = true;
      return (
        <Fragment key={`group-${slot.group}`}>
          {withDivider && <GroupDivider />}
          <div role="group" aria-label={groupLabels[slot.group]} style={{ display: 'flex', alignItems: 'center', gap: TOOLBAR_GAP_PX, flexShrink: 0 }}>
            {items.map(renderAction)}
          </div>
        </Fragment>
      );
    }
    somethingDrawn = true;
    const slotLabel = typeof slot.label === 'function' ? slot.label({ folded }) : slot.label;
    return (
      <Pinned key={`pinned-${slot.key}`} creation={slot.foldable} label={slotLabel} style={slot.style}>
        <RenderSlot render={slot.render} folded={folded} />
      </Pinned>
    );
  });

  return <>{slots}</>;
};

export default ToolbarSlots;
