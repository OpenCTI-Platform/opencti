import type { ElementType } from 'react';
import { AddOutlined, DeleteOutlined, EditOutlined, HelpOutlined, LinkOffOutlined, LinkOutlined } from '@mui/icons-material';
import Avatar from '@mui/material/Avatar';
import { deepOrange, deepPurple, green, indigo, pink, red, teal, yellow } from '@mui/material/colors';
import { LinkVariantPlus, LinkVariantRemove, Merge } from 'mdi-material-ui';
import { useTheme } from '@mui/styles';
import type { Theme } from '../../../../components/Theme';

interface IconConfig {
  color: string;
  Icon: ElementType;
  clickable: boolean;
}

/**
 * Returns the icon configuration (color, icon component, clickable flag)
 * based on the event scope and message.
 */
const getHistoryIconConfig = (
  eventScope: string | null | undefined,
  eventMessage: string,
  isRelation: boolean,
): IconConfig => {
  if (isRelation) {
    if (eventScope === 'create') {
      return { color: pink[500], Icon: LinkOutlined, clickable: true };
    }
    if (eventScope === 'delete') {
      return { color: deepPurple[500], Icon: LinkOffOutlined, clickable: true };
    }
  } else {
    if (eventScope === 'create') {
      return { color: pink[500], Icon: AddOutlined, clickable: true };
    }
    if (eventScope === 'merge') {
      return { color: teal[500], Icon: Merge, clickable: true };
    }
    if (eventScope === 'update' && eventMessage.includes('replaces')) {
      return { color: green[500], Icon: EditOutlined, clickable: true };
    }
    if (eventScope === 'update' && eventMessage.includes('changes')) {
      return { color: green[500], Icon: EditOutlined, clickable: true };
    }
    if (eventScope === 'update' && eventMessage.includes('removes')) {
      return { color: deepOrange[500], Icon: LinkVariantRemove, clickable: true };
    }
    if (eventScope === 'update') {
      return { color: indigo[500], Icon: LinkVariantPlus, clickable: true };
    }
    if (eventScope === 'delete') {
      return { color: red[500], Icon: DeleteOutlined, clickable: false };
    }
  }
  return { color: yellow[500], Icon: HelpOutlined, clickable: true };
};

interface HistoryIconProps {
  eventScope: string | null | undefined;
  eventMessage: string;
  commit: string | null | undefined;
  isRelation: boolean;
  onCommitClick: () => void;
}

/**
 * Renders the history icon avatar with the appropriate color, icon, and click behavior.
 */
const HistoryIcon = ({
  eventScope,
  eventMessage,
  commit,
  isRelation,
  onCommitClick,
}: HistoryIconProps) => {
  const theme = useTheme<Theme>();
  const { color, Icon, clickable } = getHistoryIconConfig(eventScope, eventMessage, isRelation);
  const canClick = clickable && !!commit;

  return (
    <Avatar
      sx={{
        width: 25,
        height: 25,
        backgroundColor: 'transparent',
        border: `1px solid ${color}`,
        color: theme.palette.text.primary,
        cursor: canClick ? 'pointer' : 'auto',
      }}
      onClick={canClick ? onCommitClick : undefined}
    >
      <Icon style={{ fontSize: 12 }} />
    </Avatar>
  );
};

export default HistoryIcon;
