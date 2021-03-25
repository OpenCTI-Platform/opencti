import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import { QueryRenderer } from '../../../../relay/environment';
import inject18n from '../../../../components/i18n';
import InvestigationKnowledgeGraph, {
  investigationGraphQuery,
} from './InvestigationGraph';
import Loader from '../../../../components/Loader';
import WorkspaceHeader from '../WorkspaceHeader';

const styles = () => ({
  container: {
    width: '100%',
    height: '100%',
    margin: 0,
    padding: 0,
  },
});

class InvestigationComponent extends Component {
  render() {
    const { classes, workspace } = this.props;
    return (
      <div className={classes.container}>
        <WorkspaceHeader workspace={workspace} />
        <QueryRenderer
          query={investigationGraphQuery}
          variables={{ id: workspace.id }}
          render={({ props }) => {
            if (props && props.workspace) {
              return (
                <InvestigationKnowledgeGraph workspace={props.workspace} />
              );
            }
            return <Loader />;
          }}
        />
      </div>
    );
  }
}

InvestigationComponent.propTypes = {
  workspace: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

const Investigation = createFragmentContainer(InvestigationComponent, {
  workspace: graphql`
    fragment Investigation_workspace on Workspace {
      id
      name
      description
      tags
      editContext {
        name
        focusOn
      }
    }
  `,
});

export default compose(inject18n, withStyles(styles))(Investigation);
