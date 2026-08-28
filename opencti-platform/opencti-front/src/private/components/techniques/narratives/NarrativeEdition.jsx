import React from 'react';
import * as PropTypes from 'prop-types';
import { graphql } from 'react-relay';
import { commitMutation, QueryRenderer } from '../../../../relay/environment';
import NarrativeEditionContainer from './NarrativeEditionContainer';
import { narrativeEditionOverviewFocus } from './NarrativeEditionOverview';
import Loader from '../../../../components/Loader';
import EditEntityControlledDial from '../../../../components/EditEntityControlledDial';

export const narrativeEditionQuery = graphql`
  query NarrativeEditionContainerQuery($id: String!) {
    narrative(id: $id) {
      ...NarrativeEditionContainer_narrative
    }
  }
`;

const NarrativeEdition = (props) => {
  const handleClose = () => {
    commitMutation({
      mutation: narrativeEditionOverviewFocus,
      variables: {
        id: props.narrativeId,
        input: { focusOn: '' },
      },
    });
  };

  const { narrativeId } = props;
  return (
    <QueryRenderer
      query={narrativeEditionQuery}
      variables={{ id: narrativeId }}
      render={({ props }) => {
        if (props) {
          return (
            <NarrativeEditionContainer
              narrative={props.narrative}
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

NarrativeEdition.propTypes = {
  narrativeId: PropTypes.string,
  me: PropTypes.object,
  theme: PropTypes.object,
};

export default NarrativeEdition;
