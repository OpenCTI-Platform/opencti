import React from 'react';
import { compose } from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import * as PropTypes from 'prop-types';
import inject18n from '../../../../components/i18n';

const styles = () => ({
  useSearchMessageContainer: {
    display: 'table',
    height: '100%',
    width: '100%',
  },
  useSearchMessage: {
    display: 'table-cell',
    verticalAlign: 'middle',
    textAlign: 'center',
  },
});

const StixCoreObjectUseSearchMessage = ({ t, classes }) => (
    <div className={classes.useSearchMessageContainer}>
        <span className={classes.useSearchMessage}>
            {t('Use the search functionality to find the entity you want to associate.')}
        </span>
    </div>
);

StixCoreObjectUseSearchMessage.propTypes = {
  t: PropTypes.func,
  classes: PropTypes.object,
};

export default compose(inject18n, withStyles(styles))(StixCoreObjectUseSearchMessage);
