import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Link, withRouter } from 'react-router-dom';
import { compose } from 'ramda';
import withStyles from '@mui/styles/withStyles';
import Button from '@mui/material/Button';
import { BugReportOutlined, SurroundSoundOutlined, WebAssetOutlined } from '@mui/icons-material';
import { Biohazard } from 'mdi-material-ui';
import inject18n from '../../../components/i18n';
import { UserContext } from '../../../utils/hooks/useAuth';

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

class TopMenuArsenal extends Component {
  render() {
    const { t, location, classes } = this.props;
    return (
      <UserContext.Consumer>
        {({ helper }) => (
          <div>
            {!helper.isEntityTypeHidden('Arsenal')
              && !helper.isEntityTypeHidden('Malware') && (
                <Button
                  component={Link}
                  to="/dashboard/arsenal/malwares"
                  variant={
                    location.pathname === '/dashboard/arsenal/malwares'
                      ? 'contained'
                      : 'text'
                  }
                  size="small"
                  color={
                    location.pathname === '/dashboard/arsenal/malwares'
                      ? 'secondary'
                      : 'primary'
                  }
                  classes={{ root: classes.button }}
                >
                  <Biohazard className={classes.icon} fontSize="small" />
                  {t('Malwares')}
                </Button>
            )}
            {!helper.isEntityTypeHidden('Channel') && (
              <Button
                component={Link}
                to="/dashboard/arsenal/channels"
                variant={
                  location.pathname === '/dashboard/arsenal/channels'
                    ? 'contained'
                    : 'text'
                }
                size="small"
                color={
                  location.pathname === '/dashboard/arsenal/channels'
                    ? 'secondary'
                    : 'primary'
                }
                classes={{ root: classes.button }}
              >
                <SurroundSoundOutlined
                  className={classes.icon}
                  fontSize="small"
                />
                {t('Channels')}
              </Button>
            )}
            {!helper.isEntityTypeHidden('Tool') && (
              <Button
                component={Link}
                to="/dashboard/arsenal/tools"
                variant={
                  location.pathname === '/dashboard/arsenal/tools'
                    ? 'contained'
                    : 'text'
                }
                size="small"
                color={
                  location.pathname === '/dashboard/arsenal/tools'
                    ? 'secondary'
                    : 'primary'
                }
                classes={{ root: classes.button }}
              >
                <WebAssetOutlined className={classes.icon} fontSize="small" />
                {t('Tools')}
              </Button>
            )}
            {!helper.isEntityTypeHidden('Vulnerability') && (
              <Button
                component={Link}
                to="/dashboard/arsenal/vulnerabilities"
                variant={
                  location.pathname === '/dashboard/arsenal/vulnerabilities'
                    ? 'contained'
                    : 'text'
                }
                size="small"
                color={
                  location.pathname === '/dashboard/arsenal/vulnerabilities'
                    ? 'secondary'
                    : 'primary'
                }
                classes={{ root: classes.button }}
              >
                <BugReportOutlined className={classes.icon} fontSize="small" />
                {t('Vulnerabilities')}
              </Button>
            )}
          </div>
        )}
      </UserContext.Consumer>
    );
  }
}

TopMenuArsenal.propTypes = {
  classes: PropTypes.object,
  location: PropTypes.object,
  t: PropTypes.func,
  history: PropTypes.object,
};

export default compose(
  inject18n,
  withRouter,
  withStyles(styles),
)(TopMenuArsenal);
