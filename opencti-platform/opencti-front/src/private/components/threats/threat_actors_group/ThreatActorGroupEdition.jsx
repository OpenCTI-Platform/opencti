import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { graphql } from 'react-relay';
import { commitMutation, QueryRenderer } from '../../../../relay/environment';
import inject18n from '../../../../components/i18n';
import ThreatActorGroupEditionContainer from './ThreatActorGroupEditionContainer';
import { ThreatActorGroupEditionOverviewFocus } from './ThreatActorGroupEditionOverview';
import Loader from '../../../../components/Loader';
import EditEntityControlledDial from '../../../../components/EditEntityControlledDial';

export const ThreatActorGroupEditionQuery = graphql`
  query ThreatActorGroupEditionContainerQuery($id: String!) {
    threatActorGroup(id: $id) {
      ...ThreatActorGroupEditionContainer_ThreatActorGroup
    }
  }
`;

class ThreatActorGroupEdition extends Component {
  handleClose() {
    commitMutation({
      mutation: ThreatActorGroupEditionOverviewFocus,
      variables: {
        id: this.props.threatActorGroupId,
        input: { focusOn: '' },
      },
    });
  }

  render() {
    const { threatActorGroupId } = this.props;
    return (
      <QueryRenderer
        query={ThreatActorGroupEditionQuery}
        variables={{ id: threatActorGroupId }}
        render={({ props }) => {
          if (props) {
            return (
              <ThreatActorGroupEditionContainer
                threatActorGroup={props.threatActorGroup}
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

ThreatActorGroupEdition.propTypes = {
  threatActorGroupId: PropTypes.string,
  t: PropTypes.func,
};

export default inject18n(ThreatActorGroupEdition);
