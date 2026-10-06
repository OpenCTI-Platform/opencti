import React, { Fragment } from 'react';
import { Menu, MenuContent, MenuLabel, MenuSeparator, MenuTrigger } from '@filigran/design-system';
import { type GraphMenuAction, GraphMenuActionItem } from './GraphToolbarMoreActions';

export interface GraphContextMenuSection {
  key: string;
  /** Names what the section acts on: the entity, the group, the selection. */
  label?: string;
  actions: readonly GraphMenuAction[];
}

export interface GraphContextMenuProps {
  /** Where the menu opens, in the coordinates of the graph container: nothing is open without it. */
  anchor: { x: number; y: number } | null;
  /** Accessible name of the menu. */
  label: string;
  sections: readonly GraphContextMenuSection[];
  onClose: () => void;
  /** Gives the focus back to the graph once the menu is closed. */
  onReturnFocus?: () => void;
}

/**
 * The context menu of the graph, opened by a right click (or Shift+F10, the context-menu key) on an
 * entity, a relationship, the selection or the empty canvas: every action that applies to what is
 * under the pointer, grouped, with its shortcut and, when it cannot run now, the reason why.
 */
const GraphContextMenu = ({ anchor, label, sections, onClose, onReturnFocus }: GraphContextMenuProps) => {
  const shown = sections.filter((section) => section.actions.length > 0);
  if (!anchor || shown.length === 0) return null;
  return (
    <Menu
      open
      modal={false}
      onOpenChange={(open) => {
        if (!open) onClose();
      }}
    >
      {/* FDS-WORKAROUND #64: the library Menu opens from a trigger only, so a hidden one sits at the pointer - see fds-migration/LIBRARY-FEEDBACK.md #64 */}
      <MenuTrigger asChild>
        <span
          aria-hidden
          tabIndex={-1}
          style={{ position: 'absolute', left: anchor.x, top: anchor.y, width: 1, height: 1, pointerEvents: 'none' }}
        />
      </MenuTrigger>
      <MenuContent
        align="start"
        side="bottom"
        aria-label={label}
        collisionPadding={8}
        onCloseAutoFocus={(event) => {
          event.preventDefault();
          onReturnFocus?.();
        }}
      >
        {shown.map((section, index) => (
          <Fragment key={section.key}>
            {index > 0 && <MenuSeparator />}
            {section.label && <MenuLabel>{section.label}</MenuLabel>}
            {section.actions.map((action) => <GraphMenuActionItem key={action.id} action={action} />)}
          </Fragment>
        ))}
      </MenuContent>
    </Menu>
  );
};

export default GraphContextMenu;
