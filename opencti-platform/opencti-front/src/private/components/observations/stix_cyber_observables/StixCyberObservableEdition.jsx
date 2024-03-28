import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import withStyles from '@mui/styles/withStyles';
import Drawer from '@mui/material/Drawer';
import { Create } from '@mui/icons-material';
import { graphql } from 'react-relay';
import { Button } from '@mui/material';
import { commitMutation, QueryRenderer } from '../../../../relay/environment';
import inject18n from '../../../../components/i18n';
import StixCyberObservableEditionContainer from './StixCyberObservableEditionContainer';
import { stixCyberObservableEditionOverviewFocus } from './StixCyberObservableEditionOverview';
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
  drawerPaperInGraph: {
    minHeight: '100vh',
    width: '30%',
    position: 'fixed',
    overflow: 'auto',
    transition: theme.transitions.create('width', {
      easing: theme.transitions.easing.sharp,
      duration: theme.transitions.duration.enteringScreen,
    }),
    padding: 0,
  },
});

export const stixCyberObservableEditionQuery = graphql`
  query StixCyberObservableEditionContainerQuery($id: String!) {
    stixCyberObservable(id: $id) {
      ...StixCyberObservableEditionContainer_stixCyberObservable
      ...StixCyberObservable_stixCyberObservable
    }
  }
`;

class StixCyberObservableEdition extends Component {
  constructor(props) {
    super(props);
    this.state = { open: false };
  }

  handleOpen() {
    this.setState({ open: true });
  }

  handleClose() {
    commitMutation({
      mutation: stixCyberObservableEditionOverviewFocus,
      variables: {
        id: this.props.stixCyberObservableId,
        input: { focusOn: '' },
      },
    });
    this.setState({ open: false });
  }

  renderClassic() {
    const { t, classes, stixCyberObservableId, variant, isArtifact = false } = this.props;
    return (
      <>
        <Button
          onClick={this.handleOpen.bind(this)}
          variant='outlined'
          style={{
            marginLeft: '3px',
            fontSize: 'small',
            float: 'right',
          }}
        >
          {t('Edit')} <Create />
        </Button>
        <Drawer
          open={this.state.open}
          anchor="right"
          sx={{ zIndex: 1202 }}
          elevation={1}
          classes={{ paper: classes.drawerPaper }}
          onClose={this.handleClose.bind(this)}
        >
          <QueryRenderer
            query={stixCyberObservableEditionQuery}
            variables={{ id: stixCyberObservableId }}
            render={({ props }) => {
              if (props) {
                return (
                  <StixCyberObservableEditionContainer
                    variant={variant}
                    stixCyberObservable={props.stixCyberObservable}
                    handleClose={this.handleClose.bind(this)}
                    isArtifact={isArtifact}
                  />
                );
              }
              return <Loader variant="inElement" />;
            }}
          />
        </Drawer>
      </>
    );
  }

  renderInGraph() {
    const { classes, stixCyberObservableId, open, handleClose, variant } = this.props;
    return (
      <Drawer
        open={open}
        anchor="right"
        elevation={1}
        sx={{ zIndex: 1202 }}
        classes={{ paper: classes.drawerPaperInGraph }}
        onClose={handleClose.bind(this)}
      >
        {stixCyberObservableId ? (
          <QueryRenderer
            query={stixCyberObservableEditionQuery}
            variables={{ id: stixCyberObservableId }}
            render={({ props }) => {
              if (props) {
                return (
                  <StixCyberObservableEditionContainer
                    variant={variant}
                    stixCyberObservable={props.stixCyberObservable}
                    handleClose={handleClose.bind(this)}
                  />
                );
              }
              return <Loader variant="inElement" />;
            }}
          />
        ) : (
          <div> &nbsp; </div>
        )}
      </Drawer>
    );
  }

  render() {
    if (this.props.handleClose) {
      // in a graph bar
      return this.renderInGraph();
    }
    return this.renderClassic();
  }
}

StixCyberObservableEdition.propTypes = {
  stixCyberObservableId: PropTypes.string,
  open: PropTypes.bool,
  handleClose: PropTypes.func,
  variant: PropTypes.string,
  me: PropTypes.object,
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
};

export default compose(
  inject18n,
  withStyles(styles, { withTheme: true }),
)(StixCyberObservableEdition);
