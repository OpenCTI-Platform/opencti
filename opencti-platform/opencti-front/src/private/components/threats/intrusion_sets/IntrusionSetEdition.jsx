import React from 'react';
import * as PropTypes from 'prop-types';
import { graphql } from 'react-relay';
import { commitMutation, QueryRenderer } from '../../../../relay/environment';
import IntrusionSetEditionContainer from './IntrusionSetEditionContainer';
import { intrusionSetEditionOverviewFocus } from './IntrusionSetEditionOverview';
import Loader from '../../../../components/Loader';
import EditEntityControlledDial from '../../../../components/EditEntityControlledDial';

export const intrusionSetEditionQuery = graphql`
  query IntrusionSetEditionContainerQuery($id: String!) {
    intrusionSet(id: $id) {
      ...IntrusionSetEditionContainer_intrusionSet
    }
  }
`;

const IntrusionSetEdition = (props) => {
  const handleClose = () => {
    commitMutation({
      mutation: intrusionSetEditionOverviewFocus,
      variables: {
        id: props.intrusionSetId,
        input: { focusOn: '' },
      },
    });
  };

  const { intrusionSetId } = props;
  return (
    <QueryRenderer
      query={intrusionSetEditionQuery}
      variables={{ id: intrusionSetId }}
      render={({ props }) => {
        if (props) {
          return (
            <IntrusionSetEditionContainer
              intrusionSet={props.intrusionSet}
              handleClose={handleClose.bind(this)}
              controlledDial={EditEntityControlledDial}
            />
          );
        }
        return <Loader variant="inline" />;
      }}
    />
  );
};

IntrusionSetEdition.propTypes = {
  intrusionSetId: PropTypes.string,
  theme: PropTypes.object,
};

export default IntrusionSetEdition;
