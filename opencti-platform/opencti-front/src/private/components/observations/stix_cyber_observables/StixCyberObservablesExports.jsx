import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import withStyles from '@mui/styles/withStyles';
import Slide from '@mui/material/Slide';
import { Drawer } from '@components';
import { QueryRenderer } from '../../../../relay/environment';
import StixCyberObservablesExportsContent, { stixCyberObservablesExportsContentQuery } from './StixCyberObservablesExportsContent';

const Transition = React.forwardRef((props, ref) => (
  <Slide direction="up" ref={ref} {...props} />
));
Transition.displayName = 'TransitionSlide';

const styles = (theme) => ({
  drawerPaper: {
    minHeight: '100vh',
    width: '50%',
    position: 'fixed',
    transition: theme.transitions.create('width', {
      easing: theme.transitions.easing.sharp,
      duration: theme.transitions.duration.enteringScreen,
    }),
    padding: 0,
  },
  toolbar: theme.mixins.toolbar,
});

class StixCyberObservablesExports extends Component {
  render() {
    const { classes, paginationOptions, open, handleToggle, exportContext } = this.props;
    return (
      <Drawer
        open={open}
        anchor="right"
        sx={{ zIndex: 1202 }}
        elevation={1}
        classes={{ paper: classes.drawerPaper }}
        onClose={handleToggle.bind(this)}
      >
        <QueryRenderer
          query={stixCyberObservablesExportsContentQuery}
          variables={{ count: 25, exportContext }}
          render={({ props }) => (
            <StixCyberObservablesExportsContent
              handleToggle={handleToggle.bind(this)}
              data={props}
              paginationOptions={paginationOptions}
              isOpen={open}
              exportContext={exportContext}
            />
          )}
        />
      </Drawer>
    );
  }
}

StixCyberObservablesExports.propTypes = {
  classes: PropTypes.object.isRequired,
  open: PropTypes.bool,
  handleToggle: PropTypes.func,
  paginationOptions: PropTypes.object,
  handleApplyListArgs: PropTypes.func,
  exportContext: PropTypes.object,
};

export default compose(withStyles(styles))(StixCyberObservablesExports);
