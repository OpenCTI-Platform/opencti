import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Drawer from '@material-ui/core/Drawer';
import inject18n from '../../../../components/i18n';
import { QueryRenderer } from '../../../../relay/environment';
import StixObservableRelationEditionOverview from './StixObservableRelationEditionOverview';
import Loader from '../../../../components/Loader';

const styles = (theme) => ({
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

const stixObservableRelationEditionQuery = graphql`
  query StixObservableRelationEditionQuery($id: String!) {
    stixObservableRelation(id: $id) {
      ...StixObservableRelationEditionOverview_stixObservableRelation
    }
  }
`;

export const stixObservableRelationEditionDeleteMutation = graphql`
  mutation StixObservableRelationEditionDeleteMutation($id: ID!) {
    stixObservableRelationEdit(id: $id) {
      delete
    }
  }
`;

class StixObservableRelationEdition extends Component {
  render() {
    const {
      classes,
      stixObservableRelationId,
      stixDomainEntity,
      open,
      handleClose,
      handleDelete,
    } = this.props;
    return (
      <Drawer open={open}
        anchor="right"
        classes={{ paper: classes.drawerPaper }}
        onClose={handleClose.bind(this)}>
        {stixObservableRelationId ? (
          <QueryRenderer
            query={stixObservableRelationEditionQuery}
            variables={{ id: stixObservableRelationId }}
            render={({ props }) => {
              if (props) {
                return (
                  <StixObservableRelationEditionOverview
                    stixDomainEntity={stixDomainEntity}
                    stixObservableRelation={props.stixObservableRelation}
                    handleClose={handleClose.bind(this)}
                    handleDelete={
                      typeof handleDelete === 'function'
                        ? handleDelete.bind(this)
                        : null
                    }
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
}

StixObservableRelationEdition.propTypes = {
  stixObservableRelationId: PropTypes.string,
  stixDomainEntity: PropTypes.object,
  open: PropTypes.bool,
  handleClose: PropTypes.func,
  handleDelete: PropTypes.func,
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
};

export default compose(
  inject18n,
  withStyles(styles),
)(StixObservableRelationEdition);
