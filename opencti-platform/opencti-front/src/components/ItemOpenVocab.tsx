import React, { FunctionComponent } from 'react';
import makeStyles from '@mui/styles/makeStyles';
import * as R from 'ramda';
import Tooltip from '@mui/material/Tooltip';
import { InformationOutline } from 'mdi-material-ui';
import { openVocabularies } from '../utils/Entity';
import { useFormatter } from './i18n';

const useStyles = makeStyles(() => ({
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
  type: string
  value?: string
  small: boolean
}

const ItemOpenVocab: FunctionComponent<ItemOpenVocabProps> = ({ type, value, small = true }) => {
  const { t } = useFormatter();
  const classes = useStyles();
  if (!value) {
    return (
      <span className={classes.container}>
        <pre style={{ margin: 0, paddingTop: 7, paddingBottom: 4 }}>
          {t('Unknown')}
        </pre>
        <Tooltip title={t('No value')}>
          <InformationOutline
            className={classes.icon}
            fontSize="small"
            color="secondary"
          />
        </Tooltip>
      </span>
    );
  }
  const openVocabList = openVocabularies[type];
  const openVocab = R.head(openVocabList.filter((n) => n.key === value));
  const description = openVocab && openVocab.description ? openVocab.description : t('No value');
  const preStyle = small ? { margin: 0, paddingTop: 7, paddingBottom: 4 } : { marginTop: 7 };
  return (
    <span className={classes.container}>
      <pre style={preStyle}>{value}</pre>
      <Tooltip title={t(description)}>
        <InformationOutline
          className={small ? classes.smallIcon : classes.icon}
          fontSize="small"
          color="secondary"
        />
      </Tooltip>
    </span>
  );
};

export default ItemOpenVocab;
