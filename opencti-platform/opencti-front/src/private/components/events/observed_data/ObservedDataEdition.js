import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import withStyles from '@mui/styles/withStyles';
import Drawer from '@mui/material/Drawer';
import Fab from '@mui/material/Fab';
import { Edit } from '@mui/icons-material';
import { graphql } from 'react-relay';
import inject18n from '../../../../components/i18n';
import ObservedDataEditionContainer from './ObservedDataEditionContainer';
import { commitMutation, QueryRenderer } from '../../../../relay/environment';
import { observedDataEditionOverviewFocus } from './ObservedDataEditionOverview';
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
    transition: theme.transitions.create('width', {
      easing: theme.transitions.easing.sharp,
      duration: theme.transitions.duration.enteringScreen,
    }),
    padding: 0,
  },
});

export const observedDataEditionQuery = graphql`
  query ObservedDataEditionContainerQuery($id: String!) {
    observedData(id: $id) {
      ...ObservedDataEditionContainer_observedData
    }
    settings {
      platform_enable_reference
    }
  }
`;

class ObservedDataEdition extends Component {
  constructor(props) {
    super(props);
    this.state = { open: false };
  }

  handleOpen() {
    this.setState({ open: true });
  }

  handleClose() {
    commitMutation({
      mutation: observedDataEditionOverviewFocus,
      variables: {
        id: this.props.observedDataId,
        input: { focusOn: '' },
      },
    });
    this.setState({ open: false });
  }

  render() {
    const { classes, observedDataId } = this.props;
    return (
      <div>
        <Fab
          onClick={this.handleOpen.bind(this)}
          color="secondary"
          aria-label="Edit"
          className={classes.editButton}
        >
          <Edit />
        </Fab>
        <Drawer
          open={this.state.open}
          anchor="right"
          elevation={1}
          sx={{ zIndex: 1202 }}
          classes={{ paper: classes.drawerPaper }}
          onClose={this.handleClose.bind(this)}
        >
          <QueryRenderer
            query={observedDataEditionQuery}
            variables={{ id: observedDataId }}
            render={({ props }) => {
              if (props) {
                return (
                  <ObservedDataEditionContainer
                    observedData={props.observedData}
                    enableReferences={props.settings.platform_enable_reference?.includes(
                      'Observed-Data',
                    )}
                    handleClose={this.handleClose.bind(this)}
                  />
                );
              }
              return <Loader variant="inElement" />;
            }}
          />
        </Drawer>
      </div>
    );
  }
}

ObservedDataEdition.propTypes = {
  observedDataId: PropTypes.string,
  me: PropTypes.object,
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
};

export default compose(
  inject18n,
  withStyles(styles, { withTheme: true }),
)(ObservedDataEdition);
