import React, { FunctionComponent } from 'react';
import { ContentCopyOutlined } from '@mui/icons-material';
import makeStyles from '@mui/styles/makeStyles';
import { useFormatter } from './i18n';
import { copyToClipboard } from '../utils/utils';
import { Theme } from './Theme';

const styles = makeStyles<Theme>((theme) => ({
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
}));

interface ItemCopyProps {
  content: string;
}

const ItemCopy: FunctionComponent<ItemCopyProps> = ({ content }) => {
  const { t } = useFormatter();
  const classes = styles();
  return (
    <div className={classes.container}>
      {content}
      <span
        className={classes.icon}
        onClick={() => copyToClipboard(t, content)}
      >
        <ContentCopyOutlined sx={{ fontSize: 18 }} />
      </span>
    </div>
  );
};
export default ItemCopy;
