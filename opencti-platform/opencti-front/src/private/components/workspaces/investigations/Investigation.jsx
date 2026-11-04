import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { graphql, createFragmentContainer } from 'react-relay';
import { styled } from '@mui/material/styles';
import { QueryRenderer } from '../../../../relay/environment';
import inject18n from '../../../../components/i18n';
import InvestigationGraph, { investigationGraphQuery } from './InvestigationGraph';
import Loader from '../../../../components/Loader';
import ErrorNotFound from '../../../../components/ErrorNotFound';

const Container = styled('div')(({ theme }) => ({
  width: '100%',
  height: '100%',
  marginTop: theme.spacing(1),
  padding: 0,
}));

class InvestigationComponent extends Component {
  render() {
    const { workspace } = this.props;
    return (
      <Container id="container">
        <QueryRenderer
          query={investigationGraphQuery}
          variables={{ id: workspace.id }}
          render={({ props }) => {
            if (props) {
              if (props.workspace) {
                return (
                  <InvestigationGraph
                    id={workspace.id}
                    data={props.workspace}
                  />
                );
              }
              return <ErrorNotFound />;
            }
            return <Loader />;
          }}
        />
      </Container>
    );
  }
}

InvestigationComponent.propTypes = {
  workspace: PropTypes.object,
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

export default inject18n(Investigation);
