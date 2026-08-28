import React from 'react';
import * as PropTypes from 'prop-types';
import withStyles from '@mui/styles/withStyles';
import { graphql } from 'react-relay';
import { commitMutation, QueryRenderer } from '../../../../relay/environment';
import ThreatActorGroupEditionContainer from './ThreatActorGroupEditionContainer';
import { ThreatActorGroupEditionOverviewFocus } from './ThreatActorGroupEditionOverview';
import Loader from '../../../../components/Loader';
import EditEntityControlledDial from '../../../../components/EditEntityControlledDial';

const styles = () => ({
  editButton: {
    position: 'fixed',
    bottom: 30,
    right: 30,
  },
});

export const ThreatActorGroupEditionQuery = graphql`
  query ThreatActorGroupEditionContainerQuery($id: String!) {
    threatActorGroup(id: $id) {
      ...ThreatActorGroupEditionContainer_ThreatActorGroup
    }
  }
`;

const ThreatActorGroupEdition = (props) => {
  const handleClose = () => {
    commitMutation({
      mutation: ThreatActorGroupEditionOverviewFocus,
      variables: {
        id: props.threatActorGroupId,
        input: { focusOn: '' },
      },
    });
  };

  const { threatActorGroupId } = props;
  return (
    <QueryRenderer
      query={ThreatActorGroupEditionQuery}
      variables={{ id: threatActorGroupId }}
      render={({ props }) => {
        if (props) {
          return (
            <ThreatActorGroupEditionContainer
              threatActorGroup={props.threatActorGroup}
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

ThreatActorGroupEdition.propTypes = {
  threatActorGroupId: PropTypes.string,
  theme: PropTypes.object,
};

export default withStyles(styles, { withTheme: true })(ThreatActorGroupEdition);
