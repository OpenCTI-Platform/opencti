import React, { FunctionComponent } from 'react';
import makeStyles from '@mui/styles/makeStyles';
import { InformationOutline } from 'mdi-material-ui';
import { useFormatter } from './i18n';
import type { Theme } from './Theme';
import ItemSeverity from './ItemSeverity';
import ItemPriority from './ItemPriority';
import Tag from '@common/tag/Tag';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles<Theme>(() => ({
  container: {
    margin: 0,
    padding: 0,
    display: 'flex',
  },
  icon: {
    margin: '15px 0 0 10px',
  },
  smallIcon: {
    margin: '5px 0 0 10px',
  },
}));

interface ItemOpenVocabProps {
  type: string;
  value?: string | null;
  small?: boolean;
  hideEmpty?: boolean;
  displayMode?: 'chip' | 'span';
}

const ItemOpenVocab: FunctionComponent<ItemOpenVocabProps> = ({
  type,
  value,
  small = true,
  hideEmpty = true,
  displayMode = 'span',
}) => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();

  let tag = (
    <Tag label={value || t_i18n('Unknown')} />
  );

  if (displayMode === 'chip') {
    if (type === 'case_severity_ov' || type === 'incident_severity_ov') {
      tag = <ItemSeverity label={value || t_i18n('Unknown')} severity={value} />;
    } else if (type === 'case_priority_ov') {
      tag = <ItemPriority label={value || t_i18n('Unknown')} priority={value} />;
    }
    return hideEmpty ? (
      tag
    ) : (
      <span>{tag}</span>
    );
  }

  const iconClass = small ? classes.smallIcon : classes.icon;

  return (
    <span className={classes.container}>
      {tag}
      {hideEmpty ? '' : (
        <InformationOutline
          className={iconClass}
          fontSize="small"
          color="secondary"
        />
      )}
    </span>
  );
};

export default ItemOpenVocab;
