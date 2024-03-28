import React from 'react';
import { graphql } from 'react-relay';
import { Button } from '@mui/material';
import { Create } from '@mui/icons-material';
import { useFormatter } from '../../../../components/i18n';
import { commitMutation, QueryRenderer } from '../../../../relay/environment';
import GroupingEditionContainer from './GroupingEditionContainer';
import { groupingEditionOverviewFocus } from './GroupingEditionOverview';
import Loader from '../../../../components/Loader';

export const groupingEditionQuery = graphql`
  query GroupingEditionContainerQuery($id: String!) {
    grouping(id: $id) {
      ...GroupingEditionContainer_grouping
    }
  }
`;

const GroupingEdition = ({ groupingId }) => {
  const { t_i18n } = useFormatter();
  const handleClose = () => {
    commitMutation({
      mutation: groupingEditionOverviewFocus,
      variables: {
        id: groupingId,
        input: { focusOn: '' },
      },
    });
  };
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
              controlledDial={({ onOpen }) => (
                <Button
                  style={{
                    marginLeft: '3px',
                    fontSize: 'small',
                  }}
                  variant='contained'
                  onClick={onOpen}
                  disableElevation
                >
                  {t_i18n('Edit')} <Create />
                </Button>
              )}
            />
          );
        }
        return <Loader variant="inElement" />;
      }}
    />
  );
};

export default GroupingEdition;
