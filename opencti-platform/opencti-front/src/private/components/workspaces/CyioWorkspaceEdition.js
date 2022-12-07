import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import graphql from 'babel-plugin-relay/macro';
import { QueryRenderer } from '../../../relay/environment';
import inject18n from '../../../components/i18n';
import CyioWorkspaceEditionContainer from './CyioWorkspaceEditionContainer';
import { toastGenericError } from '../../../utils/bakedToast';

const styles = (theme) => ({
  editButton: {
    position: 'fixed',
    bottom: 30,
    right: 30,
  },
  drawerPaper: {
    minHeight: '100vh',
    width: '50%',
    position: 'fixed',
    overflow: 'auto',
    backgroundColor: theme.palette.navAlt.background,
    transition: theme.transitions.create('width', {
      easing: theme.transitions.easing.sharp,
      duration: theme.transitions.duration.enteringScreen,
    }),
    padding: 0,
  },
});

export const cyioWorkspaceEditionQuery = graphql`
  query CyioWorkspaceEditionContainerQuery($id: String!) {
    workspace(id: $id) {
      ...CyioWorkspaceEditionContainer_workspace
    }
  }
`;

class CyioWorkspaceEdition extends Component {
  render() {
    const {
      history,
      workspaceId,
      displayEdit,
      handleDisplayEdit,
    } = this.props;
    return (
      <div>
        <QueryRenderer
          query={cyioWorkspaceEditionQuery}
          variables={{ id: workspaceId }}
          render={({ error, props }) => {
            if (error) {
              toastGenericError('Failed to edit Workspace');
            }
            if (props) {
              return (
                <CyioWorkspaceEditionContainer
                  history={history}
                  workspace={props.workspace}
                  displayEdit={displayEdit}
                  handleDisplayEdit={handleDisplayEdit}
                />
              );
            }
            return <></>;
          }}
        />
      </div>
    );
  }
}

CyioWorkspaceEdition.propTypes = {
  workspaceId: PropTypes.string,
  displayEdit: PropTypes.bool,
  history: PropTypes.object,
  handleDisplayEdit: PropTypes.func,
  me: PropTypes.object,
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
};

export default compose(
  inject18n,
  withStyles(styles, { withTheme: true }),
)(CyioWorkspaceEdition);
