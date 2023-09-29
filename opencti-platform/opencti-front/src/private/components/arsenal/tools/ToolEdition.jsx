import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { graphql } from 'react-relay';
import { commitMutation, QueryRenderer } from '../../../../relay/environment';
import ToolEditionContainer from './ToolEditionContainer';
import { toolEditionOverviewFocus } from './ToolEditionOverview';
import Loader from '../../../../components/Loader';

export const toolEditionQuery = graphql`
  query ToolEditionContainerQuery($id: String!) {
    tool(id: $id) {
      ...ToolEditionContainer_tool
    }
  }
`;

class ToolEdition extends Component {
  handleClose() {
    commitMutation({
      mutation: toolEditionOverviewFocus,
      variables: {
        id: this.props.toolId,
        input: { focusOn: '' },
      },
    });
  }

  render() {
    const { toolId } = this.props;
    return (
      <QueryRenderer
        query={toolEditionQuery}
        variables={{ id: toolId }}
        render={({ props }) => {
          if (props) {
            return (
              <ToolEditionContainer tool={props.tool} handleClose={this.handleClose.bind(this)} />
            );
          }
          return <Loader variant="inElement" />;
        }}
      />
    );
  }
}

ToolEdition.propTypes = {
  toolId: PropTypes.string,
  me: PropTypes.object,
  theme: PropTypes.object,
};

export default ToolEdition;
