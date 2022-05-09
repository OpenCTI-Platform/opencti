import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { graphql } from 'react-relay';
import withStyles from '@mui/styles/withStyles';
import Drawer from '@mui/material/Drawer';
import inject18n from '../../../../components/i18n';
import { QueryRenderer } from '../../../../relay/environment';
import StixSightingRelationshipEditionOverview from './StixSightingRelationshipEditionOverview';
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

const stixSightingRelationshipEditionQuery = graphql`
  query StixSightingRelationshipEditionQuery($id: String!) {
    stixSightingRelationship(id: $id) {
      ...StixSightingRelationshipEditionOverview_stixSightingRelationship
    }
    settings {
      platform_enable_reference
    }
  }
`;

export const stixSightingRelationshipEditionDeleteMutation = graphql`
  mutation StixSightingRelationshipEditionDeleteMutation($id: ID!) {
    stixSightingRelationshipEdit(id: $id) {
      delete
    }
  }
`;

class StixSightingRelationshipEdition extends Component {
  render() {
    const {
      classes,
      stixSightingRelationshipId,
      stixDomainObject,
      open,
      handleClose,
      handleDelete,
      inferred,
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
        {stixSightingRelationshipId ? (
          <QueryRenderer
            query={stixSightingRelationshipEditionQuery}
            variables={{ id: stixSightingRelationshipId }}
            render={({ props }) => {
              if (props) {
                return (
                  <StixSightingRelationshipEditionOverview
                    stixDomainObject={stixDomainObject}
                    stixSightingRelationship={props.stixSightingRelationship}
                    enableReferences={props.settings.platform_enable_reference?.includes(
                      'stix-sighting-relationship',
                    )}
                    handleClose={handleClose.bind(this)}
                    handleDelete={
                      typeof handleDelete === 'function'
                        ? handleDelete.bind(this)
                        : null
                    }
                    inferred={inferred}
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

StixSightingRelationshipEdition.propTypes = {
  stixSightingRelationshipId: PropTypes.string,
  stixDomainObject: PropTypes.object,
  open: PropTypes.bool,
  handleClose: PropTypes.func,
  handleDelete: PropTypes.func,
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
  inferred: PropTypes.bool,
  noStoreUpdate: PropTypes.bool,
};

export default compose(
  inject18n,
  withStyles(styles),
)(StixSightingRelationshipEdition);
