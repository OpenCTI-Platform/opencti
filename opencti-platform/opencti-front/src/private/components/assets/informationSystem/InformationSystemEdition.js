/* eslint-disable */
/* refactor */
import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import graphql from 'babel-plugin-relay/macro';
import { commitMutation, QueryRenderer } from '../../../../relay/environment';
import inject18n from '../../../../components/i18n';
import InformationSystemEditionContainer from './InformationSystemEditionContainer';
import { informationSystemEditionOverviewFocus } from './InformationSystemEditionOverview';
import Loader from '../../../../components/Loader';

const styles = (theme) => ({
  editButton: {
    position: 'fixed',
    bottom: 30,
    right: 30,
  },
  drawerPaper: {
    minHeight: '100vh',
    width: '50%',
    position: 'fixed',
    overflow: 'auto',
    backgroundColor: theme.palette.navAlt.background,
    transition: theme.transitions.create('width', {
      easing: theme.transitions.easing.sharp,
      duration: theme.transitions.duration.enteringScreen,
    }),
    padding: 0,
  },
});

export const informationSystemEditionQuery = graphql`
  query InformationSystemEditionContainerQuery($id: ID!) {
    softwareAsset(id: $id) {
      ...InformationSystemEditionContainer
    }
    # settings {
    #   platform_enable_reference
    # }
  }
`;

class InformationSystemEdition extends Component {
  constructor(props) {
    super(props);
    this.state = { open: false };
  }

  handleOpen() {
    this.setState({ open: true });
  }

  handleClose() {
    commitMutation({
      mutation: informationSystemEditionOverviewFocus,
      variables: {
        id: this.props.informationSystemId,
        input: { focusOn: '' },
      },
    });
    this.setState({ open: false });
  }

  render() {
    const {
      informationSystemId,
      history,
    } = this.props;
    return (
      <div>
        <QueryRenderer
          query={informationSystemEditionQuery}
          variables={{ id: informationSystemId }}
          render={({ props, retry }) => {
            if (props) {
              return (
                <InformationSystemEditionContainer
                  software={props.softwareAsset}
                  // enableReferences={props.settings.platform_enable_reference?.includes(
                  //   'Software',
                  // )}
                  history={history}
                  refreshQuery={retry}
                  handleClose={this.handleClose.bind(this)}
                />
              );
            }
            return <Loader variant="inElement" />;
          }}
        />
      </div>
    );
  }
}

InformationSystemEdition.propTypes = {
  informationSystemId: PropTypes.string,
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
};

export default compose(
  inject18n,
  withStyles(styles, { withTheme: true }),
)(InformationSystemEdition);
