import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import withStyles from '@mui/styles/withStyles';
import { graphql } from 'react-relay';
import { commitMutation, QueryRenderer } from '../../../../relay/environment';
import inject18n from '../../../../components/i18n';
import ThreatActorGroupEditionContainer from './ThreatActorGroupEditionContainer';
import { ThreatActorGroupEditionOverviewFocus } from './ThreatActorGroupEditionOverview';
import Loader from '../../../../components/Loader';

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
              />
            );
          }
          return <Loader variant="inElement" />;
        }}
      />
    );
  }
}

ThreatActorGroupEdition.propTypes = {
  threatActorGroupId: PropTypes.string,
  theme: PropTypes.object,
  t: PropTypes.func,
};

export default compose(
  inject18n,
  withStyles(styles, { withTheme: true }),
)(ThreatActorGroupEdition);
