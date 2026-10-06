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
import { GRAPH_TOOLBAR_GROUPS, type GraphToolbarAction, useGraphToolbarGroupLabels } from './useGraphToolbarActions';
import GraphToolbarOptionsList, { checkable } from './GraphToolbarOptionsList';

/** The toolbar glyphs, brought down to the size of a menu item. */
const MenuGlyph = ({ children }: { children: React.ReactNode }) => (
  <Box component="span" sx={{ display: 'inline-flex', '& svg': { fontSize: 18 } }}>{children}</Box>
);

/** What a menu of the graph lists: a toolbar action, or an action of the context menu. */
export type GraphMenuAction = Pick<GraphToolbarAction, 'id' | 'label' | 'icon' | 'shortcut' | 'pressed' | 'disabledReason' | 'badge' | 'onSelect' | 'options'>;

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

export const GraphMenuActionItem = ({ action }: { action: GraphMenuAction }) => {
  const { options } = action;
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

/**
 * The "More actions" menu closing the graph toolbar: the rare actions, and those the toolbar has
 * no room for, by group in the order of the toolbar.
 */
const GraphToolbarMoreActions = ({ actions }: { actions: readonly GraphToolbarAction[] }) => {
  const { t_i18n } = useFormatter();
  const [open, setOpen] = useState(false);
  const groupLabels = useGraphToolbarGroupLabels();
  const groups = GRAPH_TOOLBAR_GROUPS
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
      <MenuContent align="end" side="top" aria-label={t_i18n('More actions')}>
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
