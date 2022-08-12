import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import graphql from 'babel-plugin-relay/macro';
import { commitMutation, QueryRenderer } from '../../../../../relay/environment';
import inject18n from '../../../../../components/i18n';
import RemediationEditionContainer from './RemediationEditionContainer';
import Loader from '../../../../../components/Loader';

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

export const remediationEditionQuery = graphql`
  query RemediationEditionContainerQuery($id: ID!) {
    riskResponse(id: $id) {
      ...RemediationEditionContainer_risk
    }
  }
`;

export const remediationEditionDarkLightQuery = graphql`
  query RemediationEditionContainerDarkLightQuery($id: ID!) {
    riskResponse(id: $id) {
      id
      name
      # ...RemediationEditionOverview_risk
      # ...RemediationEditionDetails_risk
    }
  }
`;

class RemediationEdition extends Component {
  constructor(props) {
    super(props);
    this.state = { open: false };
  }

  handleOpen() {
    this.setState({ open: true });
  }

  handleClose() {
    commitMutation({
      // mutation: riskEditionOverviewFocus,
      variables: {
        id: this.props.riskId,
        input: { focusOn: '' },
      },
    });
    this.setState({ open: false });
  }

  render() {
    const {
      riskId,
      remediationId,
      history,
      remediation,
    } = this.props;
    return (
      <div>
        {/* <Fab
          onClick={this.handleOpen.bind(this)}
          color="secondary"
          aria-label="Edit"
          className={classes.editButton}
        >
          <Edit />
        </Fab> */}
        {/* <Drawer
          open={this.state.open}
          anchor="right"
          classes={{ paper: classes.drawerPaper }}
          onClose={this.handleClose.bind(this)}
        > */}
        <div>
        <QueryRenderer
          query={remediationEditionQuery}
          variables={{ id: riskId }}
          render={({ props }) => {
            console.log('RemediationEditionDarkLightQuery', props);
            if (props) {
              return (
                <RemediationEditionContainer
                  risk={props.riskResponse}
                  remediationId={remediationId}
                  remediation={remediation}
                  // enableReferences={props.settings.platform_enable_reference?.includes(
                    //   'Risk',
                    // )}
                  history={history}
                  handleClose={this.handleClose.bind(this)}
                />
              );
            }
            return <Loader variant="inElement" />;
          }}
        />
        {/* </Drawer> */}
        </div>
      </div>
    );
  }
}

RemediationEdition.propTypes = {
  remediationId: PropTypes.string,
  riskId: PropTypes.string,
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
  remediation: PropTypes.object,
};

export default compose(
  inject18n,
  withStyles(styles, { withTheme: true }),
)(RemediationEdition);
