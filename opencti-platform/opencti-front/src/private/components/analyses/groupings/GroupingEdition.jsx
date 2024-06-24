import React from 'react';
import { graphql } from 'react-relay';
import { commitMutation, QueryRenderer } from '../../../../relay/environment';
import GroupingEditionContainer from './GroupingEditionContainer';
import { groupingEditionOverviewFocus } from './GroupingEditionOverview';
import Loader from '../../../../components/Loader';
import EditEntityControlledDial from '../../../../components/EditEntityControlledDial';

export const groupingEditionQuery = graphql`
  query GroupingEditionContainerQuery($id: String!) {
    grouping(id: $id) {
      ...GroupingEditionContainer_grouping
    }
  }
`;

const GroupingEdition = ({ groupingId }) => {
  const handleClose = () => {
    commitMutation({
      mutation: groupingEditionOverviewFocus,
      variables: {
        id: groupingId,
        input: { focusOn: '' },
      },
    });
  };
  const EditGroupingControlledDial = (props) => (
    <EditEntityControlledDial {...props} />
  );
  return (
    <QueryRenderer
      query={groupingEditionQuery}
      variables={{ id: groupingId }}
      render={({ props }) => {
        if (props) {
          return (
            <GroupingEditionContainer
              grouping={props.grouping}
              handleClose={handleClose}
              controlledDial={EditGroupingControlledDial}
            />
          );
        }
        return <Loader variant="inElement" />;
      }}
    />
  );
};

export default GroupingEdition;
