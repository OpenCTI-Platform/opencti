import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { graphql } from 'react-relay';
import { commitMutation, QueryRenderer } from '../../../../relay/environment';
import OrganizationEditionContainer from './OrganizationEditionContainer';
import { organizationEditionOverviewFocus } from './OrganizationEditionOverview';
import Loader from '../../../../components/Loader';

export const organizationEditionQuery = graphql`
  query OrganizationEditionContainerQuery($id: String!) {
    organization(id: $id) {
      ...OrganizationEditionContainer_organization
    }
  }
`;

class OrganizationEdition extends Component {
  handleClose() {
    commitMutation({
      mutation: organizationEditionOverviewFocus,
      variables: {
        id: this.props.organizationId,
        input: { focusOn: '' },
      },
    });
  }

  render() {
    const { organizationId } = this.props;
    return (
      <QueryRenderer
        query={organizationEditionQuery}
        variables={{ id: organizationId }}
        render={({ props }) => {
          if (props) {
            return (
              <OrganizationEditionContainer organization={props.organization} handleClose={this.handleClose.bind(this)} />
            );
          }
          return <Loader variant="inElement" />;
        }}
      />
    );
  }
}

OrganizationEdition.propTypes = {
  organizationId: PropTypes.string,
};

export default OrganizationEdition;
