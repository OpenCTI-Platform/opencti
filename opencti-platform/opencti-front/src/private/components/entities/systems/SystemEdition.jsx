import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { graphql } from 'react-relay';
import { commitMutation, QueryRenderer } from '../../../../relay/environment';
import SystemEditionContainer from './SystemEditionContainer';
import { systemEditionOverviewFocus } from './SystemEditionOverview';
import Loader from '../../../../components/Loader';

export const systemEditionQuery = graphql`
  query SystemEditionContainerQuery($id: String!) {
    system(id: $id) {
      ...SystemEditionContainer_system
    }
  }
`;

class SystemEdition extends Component {
  handleClose() {
    commitMutation({
      mutation: systemEditionOverviewFocus,
      variables: {
        id: this.props.systemId,
        input: { focusOn: '' },
      },
    });
  }

  render() {
    const { systemId } = this.props;
    return (
          <QueryRenderer
            query={systemEditionQuery}
            variables={{ id: systemId }}
            render={({ props }) => {
              if (props) {
                return (
                  <SystemEditionContainer system={props.system} handleClose={this.handleClose.bind(this)} />
                );
              }
              return <Loader variant="inElement" />;
            }}
          />
    );
  }
}

SystemEdition.propTypes = {
  systemId: PropTypes.string,
};

export default SystemEdition;
