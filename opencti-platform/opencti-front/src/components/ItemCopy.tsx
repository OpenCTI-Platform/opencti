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
  containerWrap: {
    position: 'relative',
    paddingRight: 18,
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
    top: 0,
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
  value?: string;
  variant?: 'default' | 'inLine' | 'wrap';
  limit?: number;
}

const ItemCopy: FunctionComponent<ItemCopyProps> = ({
  content,
  value,
  variant = 'default',
  limit = null,
}) => {
  const { t_i18n } = useFormatter();
  const classes = useStyles();
  const textToCopy = value || content;

  const classNameVariant = () => {
    if (variant === 'inLine') return classes.containerInline;
    if (variant === 'wrap') return classes.containerWrap;
    return classes.container;
  };

  return (
    <div className={classNameVariant()}>
      {limit ? truncate(content, limit) : content}
      <span
        className={variant === 'inLine' ? classes.iconInline : classes.icon}
        onClick={(event) => {
          event.stopPropagation();
          event.preventDefault();
          copyToClipboard(t_i18n, textToCopy);
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
