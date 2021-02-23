import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Link, withRouter } from 'react-router-dom';
import { compose } from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import Button from '@material-ui/core/Button';
import inject18n from '../../../components/i18n';
import Security, {
  SETTINGS_SETACCESSES,
  SETTINGS_SETMARKINGS, TAXIIAPI_SETCOLLECTIONS,
} from '../../../utils/Security';

const styles = (theme) => ({
  button: {
    marginRight: theme.spacing(2),
    padding: '2px 5px 2px 5px',
    minHeight: 20,
    minWidth: 20,
    textTransform: 'none',
  },
  icon: {
    marginRight: theme.spacing(1),
  },
});

class TopMenuSettings extends Component {
  render() {
    const { t, location, classes } = this.props;
    return (
      <div>
        <Security needs={[TAXIIAPI_SETCOLLECTIONS]}>
            <Button
                component={Link}
                to="/dashboard/api/taxii"
                variant={
                    location.pathname.includes('/dashboard/api/taxii')
                      ? 'contained'
                      : 'text'
                }
                size="small"
                color={
                    location.pathname.includes('/dashboard/api/taxii')
                      ? 'primary'
                      : 'inherit'
                }
                classes={{ root: classes.button }}
            >
                {t('Taxii 2.1')}
            </Button>
        </Security>
      </div>
    );
  }
}

TopMenuSettings.propTypes = {
  classes: PropTypes.object,
  location: PropTypes.object,
  t: PropTypes.func,
  history: PropTypes.object,
};

export default compose(
  inject18n,
  withRouter,
  withStyles(styles),
)(TopMenuSettings);
