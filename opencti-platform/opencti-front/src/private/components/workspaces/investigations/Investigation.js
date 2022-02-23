import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { graphql, createFragmentContainer } from 'react-relay';
import withStyles from '@mui/styles/withStyles';
import { QueryRenderer } from '../../../../relay/environment';
import inject18n from '../../../../components/i18n';
import InvestigationKnowledgeGraph, {
  investigationGraphQuery,
} from './InvestigationGraph';
import Loader from '../../../../components/Loader';
import ErrorNotFound from '../../../../components/ErrorNotFound';

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
      <div className={classes.container} id="container">
        <QueryRenderer
          query={investigationGraphQuery}
          variables={{ id: workspace.id }}
          render={({ props }) => {
            if (props) {
              if (props.workspace) {
                return (
                  <InvestigationKnowledgeGraph workspace={props.workspace} />
                );
              }
              return <ErrorNotFound />;
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
      type
      name
      description
      tags
      graph_data
      editContext {
        name
        focusOn
      }
    }
  `,
});

export default compose(inject18n, withStyles(styles))(Investigation);
