import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { withRouter, Link } from 'react-router-dom';
import { compose } from 'ramda';
import withStyles from '@mui/styles/withStyles';
import Button from '@mui/material/Button';
import inject18n from '../../../components/i18n';
import Security, {
  KNOWLEDGE,
  MODULES,
  TAXIIAPI_SETCOLLECTIONS,
  SETTINGS,
} from '../../../utils/Security';

const styles = (theme) => ({
  button: {
    marginRight: theme.spacing(2),
    padding: '0 5px 0 5px',
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
                ? 'secondary'
                : 'primary'
            }
            classes={{ root: classes.button }}
          >
            {t('Entities')}
          </Button>
          <Button
            component={Link}
            to="/dashboard/data/relationships"
            variant={
              location.pathname === '/dashboard/data/relationships'
                ? 'contained'
                : 'text'
            }
            size="small"
            color={
              location.pathname === '/dashboard/data/relationships'
                ? 'secondary'
                : 'primary'
            }
            classes={{ root: classes.button }}
          >
            {t('Relationships')}
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
                ? 'secondary'
                : 'primary'
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
                ? 'secondary'
                : 'primary'
            }
            classes={{ root: classes.button }}
          >
            {t('Connectors')}
          </Button>
        </Security>
        <Security needs={[SETTINGS]}>
          <Button
            component={Link}
            to="/dashboard/data/sync"
            variant={
              location.pathname === '/dashboard/data/sync'
                ? 'contained'
                : 'text'
            }
            size="small"
            color={
              location.pathname === '/dashboard/data/sync'
                ? 'secondary'
                : 'primary'
            }
            classes={{ root: classes.button }}
          >
            {t('Synchronization')}
          </Button>
        </Security>
        <Security needs={[TAXIIAPI_SETCOLLECTIONS]}>
          <Button
            component={Link}
            to="/dashboard/data/sharing"
            variant={
              location.pathname.includes('/dashboard/data/sharing')
                ? 'contained'
                : 'text'
            }
            size="small"
            color={
              location.pathname.includes('/dashboard/data/sharing')
                ? 'secondary'
                : 'primary'
            }
            classes={{ root: classes.button }}
          >
            {t('Data sharing')}
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
