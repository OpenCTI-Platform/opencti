import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { graphql } from 'react-relay';
import withStyles from '@mui/styles/withStyles';
import Drawer from '@mui/material/Drawer';
import inject18n from '../../../../components/i18n';
import { QueryRenderer } from '../../../../relay/environment';
import StixNestedRefRelationshipEditionOverview from './StixNestedRefRelationshipEditionOverview';
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

const stixNestedRefRelationshipEditionQuery = graphql`
  query StixNestedRefRelationshipEditionQuery($id: String!) {
    stixRefRelationship(id: $id) {
      ...StixNestedRefRelationshipEditionOverview_stixRefRelationship
    }
  }
`;

class StixNestedRefRelationshipEdition extends Component {
  render() {
    const {
      classes,
      stixNestedRefRelationshipId,
      stixDomainObject,
      open,
      handleClose,
      handleDelete,
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
        {stixNestedRefRelationshipId ? (
          <QueryRenderer
            query={stixNestedRefRelationshipEditionQuery}
            variables={{ id: stixNestedRefRelationshipId }}
            render={({ props }) => {
              if (props) {
                return (
                  <StixNestedRefRelationshipEditionOverview
                    stixDomainObject={stixDomainObject}
                    stixRefRelationship={props.stixRefRelationship}
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

StixNestedRefRelationshipEdition.propTypes = {
  stixNestedRefRelationshipId: PropTypes.string,
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
)(StixNestedRefRelationshipEdition);
