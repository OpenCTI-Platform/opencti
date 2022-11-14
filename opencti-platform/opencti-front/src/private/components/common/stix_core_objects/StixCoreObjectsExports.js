import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import withStyles from '@mui/styles/withStyles';
import Slide from '@mui/material/Slide';
import Drawer from '@mui/material/Drawer';
import { QueryRenderer } from '../../../../relay/environment';
import StixCoreObjectsExportsContent, {
  stixCoreObjectsExportsContentQuery,
} from './StixCoreObjectsExportsContent';

const Transition = React.forwardRef((props, ref) => (
  <Slide direction="up" ref={ref} {...props} />
));
Transition.displayName = 'TransitionSlide';

const styles = (theme) => ({
  drawerPaper: {
    minHeight: '100vh',
    width: 310,
    padding: '0 0 20px 0',
    overflowX: 'hidden',
    zIndex: 1200,
  },
  toolbar: theme.mixins.toolbar,
});

class StixCoreObjectsExports extends Component {
  render() {
    const {
      classes,
      exportEntityType,
      paginationOptions,
      open,
      handleToggle,
      context,
      variant,
    } = this.props;
    return (
      <Drawer
        variant={variant || 'persistent'}
        open={open}
        anchor="right"
        elevation={1}
        sx={{ zIndex: 1202 }}
        classes={{ paper: classes.drawerPaper }}
        onClose={handleToggle.bind(this)}
      >
        <div className={classes.toolbar} />
        <QueryRenderer
          query={stixCoreObjectsExportsContentQuery}
          variables={{ count: 25, type: exportEntityType, context }}
          render={({ props }) => (
            <StixCoreObjectsExportsContent
              handleToggle={handleToggle}
              data={props}
              paginationOptions={paginationOptions}
              exportEntityType={exportEntityType}
              isOpen={open}
              context={context}
            />
          )}
        />
      </Drawer>
    );
  }
}

StixCoreObjectsExports.propTypes = {
  classes: PropTypes.object.isRequired,
  open: PropTypes.bool,
  handleToggle: PropTypes.func,
  exportEntityType: PropTypes.string.isRequired,
  paginationOptions: PropTypes.object,
  handleApplyListArgs: PropTypes.func,
  context: PropTypes.string,
  variant: PropTypes.string,
};

export default compose(withStyles(styles))(StixCoreObjectsExports);
