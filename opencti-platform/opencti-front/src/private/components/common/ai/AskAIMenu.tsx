import React, { type ReactNode } from 'react';
import { ExpandMoreOutlined } from '@mui/icons-material';
import { LogoXtmOneIcon } from 'filigran-icon';
import { Button, Menu, MenuContent, MenuItem, MenuTrigger } from '@filigran/design-system';
import FiligranIcon from '@components/common/FiligranIcon';
import { useFormatter } from '../../../../components/i18n';

export interface AskAIAction {
  key: string;
  label: string;
  onSelect: () => void;
  icon?: ReactNode;
  // Shown next to the label, and the item disabled, when the action cannot run.
  disabledReason?: string | null;
  testId?: string;
}

interface AskAIMenuProps {
  actions: AskAIAction[];
}

/** The Ask AI menu of an entity header: every AI action of the entity, behind one entry. */
const AskAIMenu = ({ actions }: AskAIMenuProps) => {
  const { t_i18n } = useFormatter();
  if (actions.length === 0) return null;
  return (
    <Menu>
      <MenuTrigger asChild>
        <Button
          variant="ia"
          priority="tertiary"
          size="sm"
          startIcon={<FiligranIcon icon={LogoXtmOneIcon} size={16} />}
          endIcon={<ExpandMoreOutlined fontSize="small" />}
          data-testid="ask-ai-menu"
        >
          {t_i18n('Ask AI')}
        </Button>
      </MenuTrigger>
      <MenuContent align="end" aria-label={t_i18n('Ask AI')}>
        {actions.map((action) => (
          <MenuItem
            key={action.key}
            startIcon={action.icon}
            onSelect={action.onSelect}
            disabled={!!action.disabledReason}
            title={action.disabledReason ?? undefined}
            data-testid={action.testId}
          >
            {action.disabledReason ? `${action.label} (${action.disabledReason})` : action.label}
          </MenuItem>
        ))}
      </MenuContent>
    </Menu>
  );
};

export default AskAIMenu;
