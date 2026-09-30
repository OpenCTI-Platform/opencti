import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { graphql } from 'react-relay';
import { commitMutation, QueryRenderer } from '../../../../relay/environment';
import CitizenshipDocumentEditionContainer from './CitizenshipDocumentEditionContainer';
import { citizenshipDocumentEditionOverviewFocus } from './CitizenshipDocumentEditionOverview';
import Loader from '../../../../components/Loader';
import EditEntityControlledDial from '../../../../components/EditEntityControlledDial';

export const citizenshipDocumentEditionQuery = graphql`
  query CitizenshipDocumentEditionContainerQuery($id: String!) {
    citizenshipDocument(id: $id) {
      ...CitizenshipDocumentEditionContainer_citizenshipDocument
    }
  }
`;

class CitizenshipDocumentEdition extends Component {
  handleClose() {
    commitMutation({
      mutation: citizenshipDocumentEditionOverviewFocus,
      variables: {
        id: this.props.citizenshipDocumentId,
        input: { focusOn: '' },
      },
    });
  }

  render() {
    const { citizenshipDocumentId } = this.props;
    return (
      <QueryRenderer
        query={citizenshipDocumentEditionQuery}
        variables={{ id: citizenshipDocumentId }}
        render={({ props }) => {
          if (props) {
            return (
              <CitizenshipDocumentEditionContainer
                citizenshipDocument={props.citizenshipDocument}
                handleClose={this.handleClose.bind(this)}
                controlledDial={EditEntityControlledDial}
              />
            );
          }
          return <Loader variant="inline" />;
        }}
      />
    );
  }
}

CitizenshipDocumentEdition.propTypes = {
  citizenshipDocumentId: PropTypes.string,
};

export default CitizenshipDocumentEdition;
