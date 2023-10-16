import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { graphql } from 'react-relay';
import { commitMutation, QueryRenderer } from '../../../../relay/environment';
import AttackPatternEditionContainer from './AttackPatternEditionContainer';
import { attackPatternEditionOverviewFocus } from './AttackPatternEditionOverview';
import Loader from '../../../../components/Loader';

export const attackPatternEditionQuery = graphql`
  query AttackPatternEditionContainerQuery($id: String!) {
    attackPattern(id: $id) {
      ...AttackPatternEditionContainer_attackPattern
      ...AttackPatternEditionDetails_attackPattern
    }
  }
`;

class AttackPatternEdition extends Component {
  handleClose() {
    commitMutation({
      mutation: attackPatternEditionOverviewFocus,
      variables: {
        id: this.props.attackPatternId,
        input: { focusOn: '' },
      },
    });
  }

  render() {
    const { attackPatternId } = this.props;
    return (
      <QueryRenderer
        query={attackPatternEditionQuery}
        variables={{ id: attackPatternId }}
        render={({ props }) => {
          if (props) {
            return (
              <AttackPatternEditionContainer
                attackPattern={props.attackPattern}
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

AttackPatternEdition.propTypes = {
  attackPatternId: PropTypes.string,
};

export default AttackPatternEdition;
