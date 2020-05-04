import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Drawer from '@material-ui/core/Drawer';
import inject18n from '../../../../components/i18n';
import { QueryRenderer } from '../../../../relay/environment';
import StixSightingEditionOverview from './StixSightingEditionOverview';
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

const stixSightingEditionQuery = graphql`
  query StixSightingEditionQuery($id: String!) {
    stixSighting(id: $id) {
      ...StixSightingEditionOverview_stixSighting
    }
  }
`;

export const stixSightingEditionDeleteMutation = graphql`
  mutation StixSightingEditionDeleteMutation($id: ID!) {
    stixSightingEdit(id: $id) {
      delete
    }
  }
`;

class StixSightingEdition extends Component {
  render() {
    const {
      classes,
      stixSightingId,
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
        {stixSightingId ? (
          <QueryRenderer
            query={stixSightingEditionQuery}
            variables={{ id: stixSightingId }}
            render={({ props }) => {
              if (props) {
                return (
                  <StixSightingEditionOverview
                    stixDomainEntity={stixDomainEntity}
                    stixSighting={props.stixSighting}
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

StixSightingEdition.propTypes = {
  stixSightingId: PropTypes.string,
  stixDomainEntity: PropTypes.object,
  open: PropTypes.bool,
  handleClose: PropTypes.func,
  handleDelete: PropTypes.func,
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
};

export default compose(inject18n, withStyles(styles))(StixSightingEdition);
