import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { withRouter, Link } from 'react-router-dom';
import { compose } from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import Button from '@material-ui/core/Button';
import inject18n from '../../../components/i18n';
import Security, {
  KNOWLEDGE,
  MODULES,
  TAXIIAPI_SETCOLLECTIONS,
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

class TopMenuData extends Component {
  render() {
    const { t, location, classes } = this.props;
    return (
      <div>
        <Security needs={[KNOWLEDGE]}>
          <Button
            component={Link}
            to="/dashboard/data/entities"
            variant={
              location.pathname === '/dashboard/data/entities'
                ? 'contained'
                : 'text'
            }
            size="small"
            color={
              location.pathname === '/dashboard/data/entities'
                ? 'primary'
                : 'inherit'
            }
            classes={{ root: classes.button }}
          >
            {t('Entities')}
          </Button>
          <Button
            component={Link}
            to="/dashboard/data/tasks"
            variant={
              location.pathname === '/dashboard/data/tasks'
                ? 'contained'
                : 'text'
            }
            size="small"
            color={
              location.pathname === '/dashboard/data/tasks'
                ? 'primary'
                : 'inherit'
            }
            classes={{ root: classes.button }}
          >
            {t('Background tasks')}
          </Button>
        </Security>
        <Security needs={[MODULES]}>
          <Button
            component={Link}
            to="/dashboard/data/connectors"
            variant={
              location.pathname.includes('/dashboard/data/connectors')
                ? 'contained'
                : 'text'
            }
            size="small"
            color={
              location.pathname.includes('/dashboard/data/connectors')
                ? 'primary'
                : 'inherit'
            }
            classes={{ root: classes.button }}
          >
            {t('Connectors')}
          </Button>
        </Security>
        <Security needs={[TAXIIAPI_SETCOLLECTIONS]}>
          <Button
            component={Link}
            to="/dashboard/data/taxii"
            variant={
              location.pathname === '/dashboard/data/taxii'
                ? 'contained'
                : 'text'
            }
            size="small"
            color={
              location.pathname === '/dashboard/data/taxii'
                ? 'primary'
                : 'inherit'
            }
            classes={{ root: classes.button }}
          >
            {t('TAXII API')}
          </Button>
        </Security>
      </div>
    );
  }
}

TopMenuData.propTypes = {
  classes: PropTypes.object,
  location: PropTypes.object,
  t: PropTypes.func,
  history: PropTypes.object,
};

export default compose(inject18n, withRouter, withStyles(styles))(TopMenuData);
