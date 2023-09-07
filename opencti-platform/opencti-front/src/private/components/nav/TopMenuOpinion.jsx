import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { withRouter, Link } from 'react-router-dom';
import { compose } from 'ramda';
import withStyles from '@mui/styles/withStyles';
import Button from '@mui/material/Button';
import { ArrowForwardIosOutlined, ReviewsOutlined } from '@mui/icons-material';
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

class TopMenuOpinion extends Component {
  render() {
    const {
      t,
      location,
      id: opinionId,
      classes,
    } = this.props;
    return (
      <div>
        <Button
          component={Link}
          to="/dashboard/analyses/opinions"
          variant="contained"
          size="small"
          color="primary"
          classes={{ root: classes.buttonHome }}
        >
          <ReviewsOutlined className={classes.icon} fontSize="small" />
          {t('Opinions')}
        </Button>
        <ArrowForwardIosOutlined
          color="primary"
          classes={{ root: classes.arrow }}
        />
        <Button
          component={Link}
          to={`/dashboard/analyses/opinions/${opinionId}`}
          variant={
            location.pathname === `/dashboard/analyses/opinions/${opinionId}`
              ? 'contained'
              : 'text'
          }
          size="small"
          color={
            location.pathname === `/dashboard/analyses/opinions/${opinionId}`
              ? 'secondary'
              : 'primary'
          }
          classes={{ root: classes.button }}
          disabled={!opinionId}
        >
          {t('Overview')}
        </Button>
        <Security needs={[KNOWLEDGE_KNUPLOAD, KNOWLEDGE_KNGETEXPORT]}>
          <Button
            component={Link}
            to={`/dashboard/analyses/opinions/${opinionId}/files`}
            variant={
              location.pathname
              === `/dashboard/analyses/opinions/${opinionId}/files`
                ? 'contained'
                : 'text'
            }
            size="small"
            color={
              location.pathname
              === `/dashboard/analyses/opinions/${opinionId}/files`
                ? 'secondary'
                : 'primary'
            }
            classes={{ root: classes.button }}
            disabled={!opinionId}
          >
            {t('Data')}
          </Button>
        </Security>
        <Button
          component={Link}
          to={`/dashboard/analyses/opinions/${opinionId}/history`}
          variant={
            location.pathname
            === `/dashboard/analyses/opinions/${opinionId}/history`
              ? 'contained'
              : 'text'
          }
          size="small"
          color={
            location.pathname
            === `/dashboard/analyses/opinions/${opinionId}/history`
              ? 'secondary'
              : 'primary'
          }
          classes={{ root: classes.button }}
          disabled={!opinionId}
        >
          {t('History')}
        </Button>
      </div>
    );
  }
}

TopMenuOpinion.propTypes = {
  classes: PropTypes.object,
  location: PropTypes.object,
  id: PropTypes.string,
  t: PropTypes.func,
};

export default compose(
  inject18n,
  withRouter,
  withStyles(styles),
)(TopMenuOpinion);
