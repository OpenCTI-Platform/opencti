import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { graphql } from 'react-relay';
import withStyles from '@mui/styles/withStyles';
import Drawer from '@mui/material/Drawer';
import inject18n from '../../../../components/i18n';
import { QueryRenderer } from '../../../../relay/environment';
import StixCoreRelationshipEditionOverview from './StixCoreRelationshipEditionOverview';
import Loader from '../../../../components/Loader';

const styles = (theme) => ({
  drawerPaper: {
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

const stixCoreRelationshipEditionQuery = graphql`
  query StixCoreRelationshipEditionQuery($id: String!) {
    stixCoreRelationship(id: $id) {
      ...StixCoreRelationshipEditionOverview_stixCoreRelationship
    }
    settings {
      platform_enable_reference
    }
  }
`;

export const stixCoreRelationshipEditionDeleteMutation = graphql`
  mutation StixCoreRelationshipEditionDeleteMutation($id: ID!) {
    stixCoreRelationshipEdit(id: $id) {
      delete
    }
  }
`;

class StixCoreRelationshipEdition extends Component {
  render() {
    const {
      classes,
      stixCoreRelationshipId,
      stixDomainObject,
      open,
      handleClose,
      handleDelete,
      noStoreUpdate,
    } = this.props;
    return (
      <Drawer
        open={open}
        anchor="right"
        elevation={1}
        sx={{ zIndex: 1202 }}
        classes={{ paper: classes.drawerPaper }}
        onClose={handleClose.bind(this)}
      >
        {stixCoreRelationshipId ? (
          <QueryRenderer
            query={stixCoreRelationshipEditionQuery}
            variables={{ id: stixCoreRelationshipId }}
            render={({ props }) => {
              if (props) {
                return (
                  <StixCoreRelationshipEditionOverview
                    stixDomainObject={stixDomainObject}
                    stixCoreRelationship={props.stixCoreRelationship}
                    enableReferences={props.settings.platform_enable_reference?.includes(
                      'stix-core-relationship',
                    )}
                    handleClose={handleClose.bind(this)}
                    handleDelete={
                      typeof handleDelete === 'function'
                        ? handleDelete.bind(this)
                        : null
                    }
                    noStoreUpdate={noStoreUpdate}
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

StixCoreRelationshipEdition.propTypes = {
  stixCoreRelationshipId: PropTypes.string,
  stixDomainObject: PropTypes.object,
  open: PropTypes.bool,
  handleClose: PropTypes.func,
  handleDelete: PropTypes.func,
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
  noStoreUpdate: PropTypes.bool,
};

export default compose(
  inject18n,
  withStyles(styles),
)(StixCoreRelationshipEdition);
