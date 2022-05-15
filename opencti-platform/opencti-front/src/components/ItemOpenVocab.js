import React from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import Tooltip from '@mui/material/Tooltip';
import { InformationOutline } from 'mdi-material-ui';
import { compose } from 'ramda';
import withStyles from '@mui/styles/withStyles';
import { openVocabularies } from '../utils/Entity';
import inject18n from './i18n';

const styles = () => ({
  container: {
    margin: 0,
    padding: 0,
    display: 'flex',
  },
  icon: {
    margin: '5px 0 0 10px',
  },
});

const ItemOpenVocab = (props) => {
  const { type, value, classes, t } = props;
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
  let description = t('No value');
  if (openVocab && openVocab.description) {
    description = openVocab.description;
  }
  return (
    <span className={classes.container}>
      <pre style={{ margin: 0, paddingTop: 7, paddingBottom: 4 }}>{value}</pre>
      <Tooltip title={t(description)}>
        <InformationOutline
          className={classes.icon}
          fontSize="small"
          color="secondary"
        />
      </Tooltip>
    </span>
  );
};

ItemOpenVocab.propTypes = {
  type: PropTypes.string,
  value: PropTypes.string,
};

export default compose(inject18n, withStyles(styles))(ItemOpenVocab);
