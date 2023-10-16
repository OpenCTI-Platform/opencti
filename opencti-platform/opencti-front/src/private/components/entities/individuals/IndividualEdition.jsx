import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { graphql } from 'react-relay';
import { commitMutation, QueryRenderer } from '../../../../relay/environment';
import IndividualEditionContainer from './IndividualEditionContainer';
import { individualEditionOverviewFocus } from './IndividualEditionOverview';
import Loader from '../../../../components/Loader';

export const individualEditionQuery = graphql`
  query IndividualEditionContainerQuery($id: String!) {
    individual(id: $id) {
      ...IndividualEditionContainer_individual
    }
  }
`;

class IndividualEdition extends Component {
  handleClose() {
    commitMutation({
      mutation: individualEditionOverviewFocus,
      variables: {
        id: this.props.individualId,
        input: { focusOn: '' },
      },
    });
  }

  render() {
    const { individualId } = this.props;
    return (
      <QueryRenderer
        query={individualEditionQuery}
        variables={{ id: individualId }}
        render={({ props }) => {
          if (props) {
            return (
              <IndividualEditionContainer individual={props.individual} handleClose={this.handleClose.bind(this)} />
            );
          }
          return <Loader variant="inElement" />;
        }}
      />
    );
  }
}

IndividualEdition.propTypes = {
  individualId: PropTypes.string,
};

export default IndividualEdition;
