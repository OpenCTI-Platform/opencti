import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { graphql } from 'react-relay';
import { commitMutation, QueryRenderer } from '../../../../relay/environment';
import PositionEditionContainer from './PositionEditionContainer';
import { positionEditionOverviewFocus } from './PositionEditionOverview';
import Loader from '../../../../components/Loader';

export const positionEditionQuery = graphql`
  query PositionEditionContainerQuery($id: String!) {
    position(id: $id) {
      ...PositionEditionContainer_position
    }
  }
`;

class PositionEdition extends Component {
  handleClose() {
    commitMutation({
      mutation: positionEditionOverviewFocus,
      variables: {
        id: this.props.positionId,
        input: { focusOn: '' },
      },
    });
  }

  render() {
    const { positionId } = this.props;
    return (
      <QueryRenderer
        query={positionEditionQuery}
        variables={{ id: positionId }}
        render={({ props }) => {
          if (props) {
            return (
              <PositionEditionContainer
                position={props.position}
                handleClose={this.handleClose.bind(this)}
              />
            );
          }
          return <Loader variant="inElement" />;
        }}
      />
    );
  }
}

PositionEdition.propTypes = {
  positionId: PropTypes.string,
};

export default PositionEdition;
