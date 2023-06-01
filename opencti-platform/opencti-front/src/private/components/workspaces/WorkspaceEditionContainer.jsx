import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { graphql, createFragmentContainer } from 'react-relay';
import { compose } from 'ramda';
import withStyles from '@mui/styles/withStyles';
import Typography from '@mui/material/Typography';
import IconButton from '@mui/material/IconButton';
import { Close } from '@mui/icons-material';
import inject18n from '../../../components/i18n';
import { SubscriptionAvatars } from '../../../components/Subscription';
import WorkspaceEditionOverview from './WorkspaceEditionOverview';

const styles = (theme) => ({
  header: {
    backgroundColor: theme.palette.background.nav,
    padding: '20px 20px 20px 60px',
  },
  closeButton: {
    position: 'absolute',
    top: 12,
    left: 5,
    color: 'inherit',
  },
  importButton: {
    position: 'absolute',
    top: 15,
    right: 20,
  },
  container: {
    padding: '10px 20px 20px 20px',
  },
  appBar: {
    width: '100%',
    zIndex: theme.zIndex.drawer + 1,
    borderBottom: '1px solid #5c5c5c',
  },
  title: {
    float: 'left',
  },
});

class WorkspaceEditionContainer extends Component {
  render() {
    const { t, classes, handleClose, workspace } = this.props;
    const { editContext } = workspace;
    return (
      <div>
        <div className={classes.header}>
          <IconButton
            aria-label="Close"
            className={classes.closeButton}
            onClick={handleClose.bind(this)}
            size="large"
            color="primary"
          >
            <Close fontSize="small" color="primary" />
          </IconButton>
          <Typography variant="h6" classes={{ root: classes.title }}>
            {t('Update a workspace')}
          </Typography>
          <SubscriptionAvatars context={editContext} />
          <div className="clearfix" />
        </div>
        <div className={classes.container}>
          <WorkspaceEditionOverview
            workspace={this.props.workspace}
            context={editContext}
          />
        </div>
      </div>
    );
  }
}

WorkspaceEditionContainer.propTypes = {
  handleClose: PropTypes.func,
  classes: PropTypes.object,
  workspace: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
};

const WorkspaceEditionFragment = createFragmentContainer(
  WorkspaceEditionContainer,
  {
    workspace: graphql`
      fragment WorkspaceEditionContainer_workspace on Workspace {
        id
        ...WorkspaceEditionOverview_workspace
        editContext {
          name
          focusOn
        }
      }
    `,
  },
);

export default compose(
  inject18n,
  withStyles(styles, { withTheme: true }),
)(WorkspaceEditionFragment);
