import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { withRouter, Link } from 'react-router-dom';
import { compose } from 'ramda';
import withStyles from '@mui/styles/withStyles';
import Button from '@mui/material/Button';
import { ArrowForwardIosOutlined, WorkOutline } from '@mui/icons-material';
import inject18n from '../../../components/i18n';
import Security, {
  KNOWLEDGE_KNGETEXPORT,
  KNOWLEDGE_KNUPLOAD,
} from '../../../utils/Security';

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

class TopMenuNote extends Component {
  render() {
    const {
      t,
      location,
      match: {
        params: { noteId },
      },
      classes,
    } = this.props;
    return (
      <div>
        <Button
          component={Link}
          to="/dashboard/analysis/notes"
          variant="contained"
          size="small"
          color="primary"
          classes={{ root: classes.buttonHome }}
        >
          <WorkOutline className={classes.icon} fontSize="small" />
          {t('Notes')}
        </Button>
        <ArrowForwardIosOutlined
          color="primary"
          classes={{ root: classes.arrow }}
        />
        <Button
          component={Link}
          to={`/dashboard/analysis/notes/${noteId}`}
          variant={
            location.pathname === `/dashboard/analysis/notes/${noteId}`
              ? 'contained'
              : 'text'
          }
          size="small"
          color={
            location.pathname === `/dashboard/analysis/notes/${noteId}`
              ? 'secondary'
              : 'primary'
          }
          classes={{ root: classes.button }}
        >
          {t('Overview')}
        </Button>
        <Security needs={[KNOWLEDGE_KNUPLOAD, KNOWLEDGE_KNGETEXPORT]}>
          <Button
            component={Link}
            to={`/dashboard/analysis/notes/${noteId}/files`}
            variant={
              location.pathname === `/dashboard/analysis/notes/${noteId}/files`
                ? 'contained'
                : 'text'
            }
            size="small"
            color={
              location.pathname === `/dashboard/analysis/notes/${noteId}/files`
                ? 'secondary'
                : 'primary'
            }
            classes={{ root: classes.button }}
          >
            {t('Data')}
          </Button>
        </Security>
        <Button
          component={Link}
          to={`/dashboard/analysis/notes/${noteId}/history`}
          variant={
            location.pathname === `/dashboard/analysis/notes/${noteId}/history`
              ? 'contained'
              : 'text'
          }
          size="small"
          color={
            location.pathname === `/dashboard/analysis/notes/${noteId}/history`
              ? 'secondary'
              : 'primary'
          }
          classes={{ root: classes.button }}
        >
          {t('History')}
        </Button>
      </div>
    );
  }
}

TopMenuNote.propTypes = {
  classes: PropTypes.object,
  location: PropTypes.object,
  match: PropTypes.object,
  t: PropTypes.func,
  history: PropTypes.object,
};

export default compose(inject18n, withRouter, withStyles(styles))(TopMenuNote);
