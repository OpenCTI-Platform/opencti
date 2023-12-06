import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import withStyles from '@mui/styles/withStyles';
import { graphql } from 'react-relay';
import { Button } from '@mui/material';
import { Create } from '@mui/icons-material';
import { commitMutation, QueryRenderer } from '../../../../relay/environment';
import inject18n from '../../../../components/i18n';
import ThreatActorGroupEditionContainer from './ThreatActorGroupEditionContainer';
import { ThreatActorGroupEditionOverviewFocus } from './ThreatActorGroupEditionOverview';
import Loader from '../../../../components/Loader';

const styles = () => ({
  actionBtns: {
    marginLeft: '3px',
    fontSize: 'small',
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
    const { classes, t, threatActorGroupId } = this.props;
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
                controlledDial={({ onOpen }) => (
                  <Button
                    className={classes.actionBtns}
                    variant='outlined'
                    onClick={onOpen}
                  >
                    {t('Edit')} <Create />
                  </Button>
                )}
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
