import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Drawer from '@material-ui/core/Drawer';
import inject18n from '../../../../components/i18n';
import { QueryRenderer } from '../../../../relay/environment';
import StixRelationEditionOverview from './StixRelationEditionOverview';
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

const stixRelationEditionQuery = graphql`
  query StixRelationEditionQuery($id: String!) {
    stixRelation(id: $id) {
      ...StixRelationEditionOverview_stixRelation
    }
  }
`;

export const stixRelationEditionDeleteMutation = graphql`
  mutation StixRelationEditionDeleteMutation($id: ID!) {
    stixRelationEdit(id: $id) {
      delete
    }
  }
`;

class StixRelationEdition extends Component {
  render() {
    const {
      classes,
      stixRelationId,
      stixDomainEntity,
      open,
      handleClose,
      handleDelete,
    } = this.props;
    return (
      <Drawer
        open={open}
        anchor="right"
        classes={{ paper: classes.drawerPaper }}
        onClose={handleClose.bind(this)}
      >
        {stixRelationId ? (
          <QueryRenderer
            query={stixRelationEditionQuery}
            variables={{ id: stixRelationId }}
            render={({ props }) => {
              if (props) {
                return (
                  <StixRelationEditionOverview
                    stixDomainEntity={stixDomainEntity}
                    stixRelation={props.stixRelation}
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

StixRelationEdition.propTypes = {
  stixRelationId: PropTypes.string,
  stixDomainEntity: PropTypes.object,
  open: PropTypes.bool,
  handleClose: PropTypes.func,
  handleDelete: PropTypes.func,
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
};

export default compose(inject18n, withStyles(styles))(StixRelationEdition);
