import React, { Fragment, useState } from 'react';
import {
  IconButton,
  Menu,
  MenuContent,
  MenuItem,
  MenuLabel,
  MenuSeparator,
  MenuSub,
  MenuSubContent,
  MenuSubTrigger,
  MenuTrigger,
  Text,
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from '@filigran/design-system';
import { MoreVert } from '@mui/icons-material';
import Box from '@mui/material/Box';
import { useTheme } from '@mui/material/styles';
import { useFormatter } from '../../i18n';
import type { Theme } from '../../Theme';
import type { GraphToolbarAction } from './useGraphToolbarActions';
import { RenderFunction, type ToolbarAction } from '../ToolbarShell';
import GraphToolbarOptionsList, { checkable } from './GraphToolbarOptionsList';

/** The toolbar glyphs, brought down to the size of a menu item. */
const MenuGlyph = ({ children }: { children: React.ReactNode }) => (
  <Box component="span" sx={{ display: 'inline-flex', '& svg': { fontSize: 18 } }}>{children}</Box>
);

/** What a menu of the graph lists: a toolbar action, or an action of the context menu. */
export type GraphMenuAction = Pick<GraphToolbarAction, 'id' | 'label' | 'icon' | 'shortcut' | 'pressed' | 'disabledReason' | 'badge' | 'onSelect' | 'options' | 'submenu'>;

const ActionLabel = ({ action }: { action: GraphMenuAction }) => {
  const theme = useTheme<Theme>();
  return (
    <span style={{ display: 'flex', flexDirection: 'column' }}>
      <span>{action.badge ? `${action.label} (${action.badge})` : action.label}</span>
      {action.disabledReason && (
        <Text variant="content-caption" as="span" style={{ color: theme.palette.text.secondary }}>{action.disabledReason}</Text>
      )}
    </span>
  );
};

const FOCUSABLE = 'input, select, textarea, button, a[href], [tabindex]:not([tabindex="-1"])';

const moveFocusWithin = (container: HTMLElement, step: 1 | -1, event: { preventDefault: () => void }) => {
  const fields = Array.from(container.querySelectorAll<HTMLElement>(FOCUSABLE))
    .filter((field) => !(field as HTMLButtonElement).disabled && !field.closest('[hidden], [aria-hidden="true"]'));
  event.preventDefault();
  if (fields.length === 0) return;
  const index = fields.indexOf(document.activeElement as HTMLElement);
  let next = step === 1 ? 0 : fields.length - 1;
  if (index >= 0) next = (index + step + fields.length) % fields.length;
  fields[next].focus();
};

export const GraphMenuActionItem = ({ action }: { action: GraphMenuAction }) => {
  const { options, submenu } = action;
  if (submenu && !action.disabledReason) {
    return (
      <MenuSub>
        <MenuSubTrigger startIcon={<MenuGlyph>{action.icon}</MenuGlyph>}>
          <ActionLabel action={action} />
        </MenuSubTrigger>
        <MenuSubContent>
          {/* FDS-WORKAROUND #86: a submenu takes the arrow and letter keys of a field inside it — see fds-migration/LIBRARY-FEEDBACK.md #86 */}
          {/* eslint-disable-next-line jsx-a11y/no-static-element-interactions */}
          <div
            onKeyDown={(event) => {
              // Escape closes the menu.
              if (event.key === 'Escape') return;
              event.stopPropagation();
              // Tab and Shift+Tab move between the fields of the control, wrapping around: the menu keeps the focus,
              // as any menu does, without trapping it on one field.
              if (event.key === 'Tab') moveFocusWithin(event.currentTarget, event.shiftKey ? -1 : 1, event);
            }}
          >
            <RenderFunction render={submenu} />
          </div>
        </MenuSubContent>
      </MenuSub>
    );
  }
  if (options && !action.disabledReason) {
    return (
      <MenuSub>
        <MenuSubTrigger startIcon={<MenuGlyph>{action.icon}</MenuGlyph>}>
          <ActionLabel action={action} />
        </MenuSubTrigger>
        <MenuSubContent>
          <GraphToolbarOptionsList options={options} />
        </MenuSubContent>
      </MenuSub>
    );
  }
  return (
    <MenuItem
      startIcon={<MenuGlyph>{action.icon}</MenuGlyph>}
      // The trailing slot holds the check of a toggle that is on, or else the shortcut.
      endIcon={action.shortcut && !action.pressed ? <Text variant="content-caption" as="kbd">{action.shortcut}</Text> : undefined}
      {...checkable(action.pressed)}
      aria-keyshortcuts={action.shortcut}
      selected={!!action.pressed}
      disabled={!!action.disabledReason}
      onSelect={() => action.onSelect?.()}
    >
      <ActionLabel action={action} />
    </MenuItem>
  );
};

interface GraphToolbarMoreActionsProps<G extends string> {
  actions: readonly ToolbarAction<G>[];
  /** Order of the groups, as in the toolbar. */
  groups: readonly G[];
  groupLabels: Record<G, string>;
}

/**
 * The "More actions" menu closing a docked toolbar: the rare actions, and those the toolbar has
 * no room for, by group in the order of the toolbar.
 */
const GraphToolbarMoreActions = <G extends string>({ actions, groups: groupOrder, groupLabels }: GraphToolbarMoreActionsProps<G>) => {
  const { t_i18n } = useFormatter();
  const [open, setOpen] = useState(false);
  const groups = groupOrder
    .map((group) => ({ group, items: actions.filter((action) => action.group === group) }))
    .filter(({ items }) => items.length > 0);
  if (groups.length === 0) return null;
  return (
    <Menu open={open} onOpenChange={setOpen} modal={false}>
      <Tooltip>
        <TooltipTrigger asChild>
          <MenuTrigger asChild>
            <IconButton priority="tertiary" aria-label={t_i18n('More actions')} icon={<MoreVert />} />
          </MenuTrigger>
        </TooltipTrigger>
        <TooltipContent side="top">{t_i18n('More actions')}</TooltipContent>
      </Tooltip>
      {/* Like the context menu, 8 px inside the window: a list taller than the room above the toolbar scrolls there. */}
      <MenuContent align="end" side="top" collisionPadding={8} aria-label={t_i18n('More actions')}>
        {groups.map(({ group, items }, index) => (
          <Fragment key={group}>
            {index > 0 && <MenuSeparator />}
            <MenuLabel>{groupLabels[group]}</MenuLabel>
            {items.map((action) => <GraphMenuActionItem key={action.id} action={action} />)}
          </Fragment>
        ))}
      </MenuContent>
    </Menu>
  );
};

export default GraphToolbarMoreActions;
