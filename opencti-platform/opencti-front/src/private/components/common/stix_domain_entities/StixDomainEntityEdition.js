import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Drawer from '@material-ui/core/Drawer';
import inject18n from '../../../../components/i18n';
import { QueryRenderer } from '../../../../relay/environment';
import StixDomainEntityEditionOverview from './StixDomainEntityEditionOverview';
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

const stixDomainEntityEditionQuery = graphql`
  query StixDomainEntityEditionQuery($id: String!) {
    stixDomainEntity(id: $id) {
      ...StixDomainEntityEditionOverview_stixDomainEntity
    }
  }
`;

class StixDomainEntityEdition extends Component {
  render() {
    const {
      classes,
      stixDomainEntityId,
      open,
      handleClose,
      handleDelete,
      variant,
    } = this.props;
    return (
      <Drawer
        open={open}
        anchor="right"
        classes={{ paper: classes.drawerPaper }}
        onClose={handleClose.bind(this)}
      >
        {stixDomainEntityId ? (
          <QueryRenderer
            query={stixDomainEntityEditionQuery}
            variables={{ id: stixDomainEntityId }}
            render={({ props }) => {
              if (props) {
                return (
                  <StixDomainEntityEditionOverview variant={variant}
                    stixDomainEntity={props.stixDomainEntity}
                    handleClose={handleClose.bind(this)}
                    handleDelete={
                      typeof handleDelete === 'function'
                        ? handleDelete.bind(this)
                        : null
                    }
                  />
                );
              }
              return <Loader variant='inElement' />;
            }}
          />
        ) : (
          <div> &nbsp; </div>
        )}
      </Drawer>
    );
  }
}

StixDomainEntityEdition.propTypes = {
  variant: PropTypes.string,
  stixDomainEntityId: PropTypes.string,
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
)(StixDomainEntityEdition);
