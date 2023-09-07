import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { withRouter, Link } from 'react-router-dom';
import { compose } from 'ramda';
import withStyles from '@mui/styles/withStyles';
import Button from '@mui/material/Button';
import { ArrowForwardIosOutlined, WebAssetOutlined } from '@mui/icons-material';
import inject18n from '../../../components/i18n';
import Security from '../../../utils/Security';
import {
  KNOWLEDGE_KNGETEXPORT,
  KNOWLEDGE_KNUPLOAD,
} from '../../../utils/hooks/useGranted';

const styles = (theme) => ({
  buttonHome: {
    marginRight: theme.spacing(2),
    padding: '0 5px 0 5px',
    minHeight: 20,
    textTransform: 'none',
  },
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
  arrow: {
    verticalAlign: 'middle',
    marginRight: 10,
  },
});

class TopMenuTool extends Component {
  render() {
    const {
      t,
      location,
      id: toolId,
      classes,
    } = this.props;
    return (
      <div>
        <Button
          component={Link}
          to="/dashboard/arsenal/tools"
          variant="contained"
          size="small"
          color="primary"
          classes={{ root: classes.buttonHome }}
        >
          <WebAssetOutlined className={classes.icon} fontSize="small" />
          {t('Tools')}
        </Button>
        <ArrowForwardIosOutlined
          color="primary"
          classes={{ root: classes.arrow }}
        />
        <Button
          component={Link}
          to={`/dashboard/arsenal/tools/${toolId}`}
          variant={
            location.pathname === `/dashboard/arsenal/tools/${toolId}`
              ? 'contained'
              : 'text'
          }
          size="small"
          color={
            location.pathname === `/dashboard/arsenal/tools/${toolId}`
              ? 'secondary'
              : 'primary'
          }
          classes={{ root: classes.button }}
          disabled={!toolId}
        >
          {t('Overview')}
        </Button>
        <Button
          component={Link}
          to={`/dashboard/arsenal/tools/${toolId}/knowledge`}
          variant={
            location.pathname.includes(
              `/dashboard/arsenal/tools/${toolId}/knowledge`,
            )
              ? 'contained'
              : 'text'
          }
          size="small"
          color={
            location.pathname.includes(
              `/dashboard/arsenal/tools/${toolId}/knowledge`,
            )
              ? 'secondary'
              : 'primary'
          }
          classes={{ root: classes.button }}
          disabled={!toolId}
        >
          {t('Knowledge')}
        </Button>
        <Button
          component={Link}
          to={`/dashboard/arsenal/tools/${toolId}/analyses`}
          variant={
            location.pathname === `/dashboard/arsenal/tools/${toolId}/analyses`
              ? 'contained'
              : 'text'
          }
          size="small"
          color={
            location.pathname === `/dashboard/arsenal/tools/${toolId}/analyses`
              ? 'secondary'
              : 'primary'
          }
          classes={{ root: classes.button }}
          disabled={!toolId}
        >
          {t('Analyses')}
        </Button>
        <Security needs={[KNOWLEDGE_KNUPLOAD, KNOWLEDGE_KNGETEXPORT]}>
          <Button
            component={Link}
            to={`/dashboard/arsenal/tools/${toolId}/files`}
            variant={
              location.pathname === `/dashboard/arsenal/tools/${toolId}/files`
                ? 'contained'
                : 'text'
            }
            size="small"
            color={
              location.pathname === `/dashboard/arsenal/tools/${toolId}/files`
                ? 'secondary'
                : 'primary'
            }
            classes={{ root: classes.button }}
            disabled={!toolId}
          >
            {t('Data')}
          </Button>
        </Security>
        <Button
          component={Link}
          to={`/dashboard/arsenal/tools/${toolId}/history`}
          variant={
            location.pathname === `/dashboard/arsenal/tools/${toolId}/history`
              ? 'contained'
              : 'text'
          }
          size="small"
          color={
            location.pathname === `/dashboard/arsenal/tools/${toolId}/history`
              ? 'secondary'
              : 'primary'
          }
          classes={{ root: classes.button }}
          disabled={!toolId}
        >
          {t('History')}
        </Button>
      </div>
    );
  }
}

TopMenuTool.propTypes = {
  classes: PropTypes.object,
  location: PropTypes.object,
  t: PropTypes.func,
  id: PropTypes.string,
};

export default compose(inject18n, withRouter, withStyles(styles))(TopMenuTool);
