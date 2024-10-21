import React, { FunctionComponent } from 'react';
import { ContentCopyOutlined } from '@mui/icons-material';
import makeStyles from '@mui/styles/makeStyles';
import { useFormatter } from './i18n';
import { copyToClipboard } from '../utils/utils';
import type { Theme } from './Theme';
import { truncate } from '../utils/String';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles<Theme>((theme) => ({
  containerInline: {
    position: 'relative',
    padding: '2px 25px 2px 5px',
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    backgroundColor: theme.palette.background.accent,
    fontFamily: 'Consolas, monaco, monospace',
    fontSize: 12,
  },
  container: {
    position: 'relative',
    paddingRight: 18,
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
  icon: {
    position: 'absolute',
    right: 0,
    cursor: 'pointer',
    '&:hover': {
      color: theme.palette.primary.main,
    },
  },
  iconInline: {
    position: 'absolute',
    right: 5,
    top: 4,
    cursor: 'pointer',
    '&:hover': {
      color: theme.palette.primary.main,
    },
  },
}));

interface ItemCopyProps {
  content: string;
  variant?: string;
  limit?: number;
}

const ItemCopy: FunctionComponent<ItemCopyProps> = ({
  content,
  variant,
  limit = null,
}) => {
  const { t_i18n } = useFormatter();
  const classes = useStyles();
  return (
    <div
      className={
        variant === 'inLine' ? classes.containerInline : classes.container
      }
    >
      {limit ? truncate(content, limit) : content}
      <span
        className={variant === 'inLine' ? classes.iconInline : classes.icon}
        onClick={(event) => {
          event.stopPropagation();
          event.preventDefault();
          copyToClipboard(t_i18n, content);
        }}
      >
        <ContentCopyOutlined
          color="primary"
          sx={{ fontSize: variant === 'inLine' ? 12 : 18 }}
        />
      </span>
    </div>
  );
};
export default ItemCopy;
