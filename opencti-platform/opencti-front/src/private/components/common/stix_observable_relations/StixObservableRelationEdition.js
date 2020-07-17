import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Drawer from '@material-ui/core/Drawer';
import inject18n from '../../../../components/i18n';
import { QueryRenderer } from '../../../../relay/environment';
import StixCyberObservableRelationEditionOverview from './StixCyberObservableRelationEditionOverview';
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

const stixCyberObservableRelationEditionQuery = graphql`
  query StixCyberObservableRelationEditionQuery($id: String!) {
    stixCyberObservableRelation(id: $id) {
      ...StixCyberObservableRelationEditionOverview_stixCyberObservableRelation
    }
  }
`;

export const stixCyberObservableRelationEditionDeleteMutation = graphql`
  mutation StixCyberObservableRelationEditionDeleteMutation($id: ID!) {
    stixCyberObservableRelationEdit(id: $id) {
      delete
    }
  }
`;

class StixCyberObservableRelationEdition extends Component {
  render() {
    const {
      classes,
      stixCyberObservableRelationId,
      stixDomainObject,
      open,
      handleClose,
      handleDelete,
    } = this.props;
    return (
      <Drawer open={open}
        anchor="right"
        classes={{ paper: classes.drawerPaper }}
        onClose={handleClose.bind(this)}>
        {stixCyberObservableRelationId ? (
          <QueryRenderer
            query={stixCyberObservableRelationEditionQuery}
            variables={{ id: stixCyberObservableRelationId }}
            render={({ props }) => {
              if (props) {
                return (
                  <StixCyberObservableRelationEditionOverview
                    stixDomainObject={stixDomainObject}
                    stixCyberObservableRelation={props.stixCyberObservableRelation}
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

StixCyberObservableRelationEdition.propTypes = {
  stixCyberObservableRelationId: PropTypes.string,
  stixDomainObject: PropTypes.object,
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
)(StixCyberObservableRelationEdition);
