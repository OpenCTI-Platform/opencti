import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import Slide from '@material-ui/core/Slide';
import Drawer from '@material-ui/core/Drawer';
import { QueryRenderer } from '../../../../relay/environment';
import StixDomainEntitiesExportsContent, {
  stixDomainEntitiesExportsContentQuery,
} from './StixDomainEntitiesExportsContent';

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
    zIndex: 0,
    backgroundColor: theme.palette.navAlt.background,
  },
  toolbar: theme.mixins.toolbar,
});

class StixDomainEntitiesExports extends Component {
  render() {
    const {
      classes,
      exportEntityType,
      paginationOptions,
      open,
      handleToggle,
    } = this.props;
    return (
      <Drawer
        variant="persistent"
        open={open}
        anchor="right"
        classes={{ paper: classes.drawerPaper }}
        onClose={handleToggle.bind(this)}
      >
        <div className={classes.toolbar} />
        <QueryRenderer
          query={stixDomainEntitiesExportsContentQuery}
          variables={{ count: 25, type: exportEntityType }}
          render={({ props }) => (
            <StixDomainEntitiesExportsContent
              handleToggle={handleToggle.bind(this)}
              data={props}
              paginationOptions={paginationOptions}
              exportEntityType={exportEntityType}
            />
          )}
        />
      </Drawer>
    );
  }
}

StixDomainEntitiesExports.propTypes = {
  classes: PropTypes.object.isRequired,
  open: PropTypes.bool,
  handleToggle: PropTypes.func,
  exportEntityType: PropTypes.string.isRequired,
  paginationOptions: PropTypes.object,
  handleApplyListArgs: PropTypes.func,
};

export default compose(withStyles(styles))(StixDomainEntitiesExports);
