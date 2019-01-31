import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Drawer from '@material-ui/core/Drawer';
import inject18n from '../../../components/i18n';
import { QueryRenderer } from '../../../relay/environment';
import StixRelationEditionOverview from './StixRelationEditionOverview';

const styles = theme => ({
  drawerPaper: {
    minHeight: '100vh',
    width: '30%',
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

const stixRelationEditionQuery = graphql`
    query StixRelationEditionQuery($id: String!) {
        stixRelation(id: $id) {
            ...StixRelationEditionOverview_stixRelation
        }
        me {
            ...StixRelationEditionOverview_me
        }
    }
`;

export const stixRelationEditionDeleteMutation = graphql`
    mutation StixRelationCreationDeleteMutation($id: ID!) {
        stixRelationEdit(id: $id) {
            delete
        }
    }
`;

class StixRelationEdition extends Component {
  render() {
    const {
      classes, stixRelationId, open, handleClose, handleDelete, variant,
    } = this.props;
    return (
      <Drawer open={open} anchor='right' classes={{ paper: classes.drawerPaper }} onClose={handleClose.bind(this)}>
        {stixRelationId
          ? <QueryRenderer
          query={stixRelationEditionQuery}
          variables={{ id: stixRelationId }}
          render={({ props }) => {
            if (props) {
              return (
                <StixRelationEditionOverview
                  variant={variant}
                  me={props.me}
                  stixRelation={props.stixRelation}
                  handleClose={handleClose.bind(this)}
                  handleDelete={handleDelete.bind(this)}
                />
              );
            }
            return <div> &nbsp; </div>;
          }}
        /> : ''}
      </Drawer>
    );
  }
}

StixRelationEdition.propTypes = {
  variant: PropTypes.string,
  stixRelationId: PropTypes.string,
  open: PropTypes.bool,
  handleClose: PropTypes.func,
  handleDelete: PropTypes.func,
  classes: PropTypes.object,
  me: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
};

export default compose(
  inject18n,
  withStyles(styles),
)(StixRelationEdition);
