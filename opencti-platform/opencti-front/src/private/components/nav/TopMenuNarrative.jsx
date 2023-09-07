import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { withRouter, Link } from 'react-router-dom';
import { compose } from 'ramda';
import withStyles from '@mui/styles/withStyles';
import Button from '@mui/material/Button';
import {
  ArrowForwardIosOutlined,
  SpeakerNotesOutlined,
} from '@mui/icons-material';
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

class TopMenuNarrative extends Component {
  render() {
    const {
      t,
      location,
      id: narrativeId,
      classes,
    } = this.props;
    return (
      <div>
        <Button
          component={Link}
          to="/dashboard/techniques/narratives"
          variant="contained"
          size="small"
          color="primary"
          classes={{ root: classes.buttonHome }}
        >
          <SpeakerNotesOutlined className={classes.icon} fontSize="small" />
          {t('Narratives')}
        </Button>
        <ArrowForwardIosOutlined
          color="primary"
          classes={{ root: classes.arrow }}
        />
        <Button
          component={Link}
          to={`/dashboard/techniques/narratives/${narrativeId}`}
          variant={
            location.pathname
            === `/dashboard/techniques/narratives/${narrativeId}`
              ? 'contained'
              : 'text'
          }
          size="small"
          color={
            location.pathname
            === `/dashboard/techniques/narratives/${narrativeId}`
              ? 'secondary'
              : 'primary'
          }
          classes={{ root: classes.button }}
          disabled={!narrativeId}
        >
          {t('Overview')}
        </Button>
        <Button
          component={Link}
          to={`/dashboard/techniques/narratives/${narrativeId}/knowledge`}
          variant={
            location.pathname.includes(
              `/dashboard/techniques/narratives/${narrativeId}/knowledge`,
            )
              ? 'contained'
              : 'text'
          }
          size="small"
          color={
            location.pathname.includes(
              `/dashboard/techniques/narratives/${narrativeId}/knowledge`,
            )
              ? 'secondary'
              : 'primary'
          }
          classes={{ root: classes.button }}
          disabled={!narrativeId}
        >
          {t('Knowledge')}
        </Button>
        <Button
          component={Link}
          to={`/dashboard/techniques/narratives/${narrativeId}/analyses`}
          variant={
            location.pathname
            === `/dashboard/techniques/narratives/${narrativeId}/analyses`
              ? 'contained'
              : 'text'
          }
          size="small"
          color={
            location.pathname
            === `/dashboard/techniques/narratives/${narrativeId}/analyses`
              ? 'secondary'
              : 'primary'
          }
          classes={{ root: classes.button }}
          disabled={!narrativeId}
        >
          {t('Analyses')}
        </Button>
        <Security needs={[KNOWLEDGE_KNUPLOAD, KNOWLEDGE_KNGETEXPORT]}>
          <Button
            component={Link}
            to={`/dashboard/techniques/narratives/${narrativeId}/files`}
            variant={
              location.pathname
              === `/dashboard/techniques/narratives/${narrativeId}/files`
                ? 'contained'
                : 'text'
            }
            size="small"
            color={
              location.pathname
              === `/dashboard/techniques/narratives/${narrativeId}/files`
                ? 'secondary'
                : 'primary'
            }
            classes={{ root: classes.button }}
            disabled={!narrativeId}
          >
            {t('Data')}
          </Button>
        </Security>
        <Button
          component={Link}
          to={`/dashboard/techniques/narratives/${narrativeId}/history`}
          variant={
            location.pathname
            === `/dashboard/techniques/narratives/${narrativeId}/history`
              ? 'contained'
              : 'text'
          }
          size="small"
          color={
            location.pathname
            === `/dashboard/techniques/narratives/${narrativeId}/history`
              ? 'secondary'
              : 'primary'
          }
          classes={{ root: classes.button }}
          disabled={!narrativeId}
        >
          {t('History')}
        </Button>
      </div>
    );
  }
}

TopMenuNarrative.propTypes = {
  classes: PropTypes.object,
  location: PropTypes.object,
  t: PropTypes.func,
  id: PropTypes.string,
};

export default compose(
  inject18n,
  withRouter,
  withStyles(styles),
)(TopMenuNarrative);
