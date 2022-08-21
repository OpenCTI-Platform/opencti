import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import withStyles from '@mui/styles/withStyles';
import Slide from '@mui/material/Slide';
import Drawer from '@mui/material/Drawer';
import { QueryRenderer } from '../../../../relay/environment';
import StixCoreRelationshipsExportsContent, {
  stixCoreRelationshipsExportsContentQuery,
} from './StixCoreRelationshipsExportsContent';

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

class StixCoreRelationshipsExports extends Component {
  render() {
    const { classes, paginationOptions, open, handleToggle, context } = this.props;
    return (
      <Drawer
        variant="persistent"
        open={open}
        anchor="right"
        elevation={1}
        sx={{ zIndex: 1202 }}
        classes={{ paper: classes.drawerPaper }}
        onClose={handleToggle.bind(this)}
      >
        <div className={classes.toolbar} />
        <QueryRenderer
          query={stixCoreRelationshipsExportsContentQuery}
          variables={{ count: 25, type: 'stix-core-relationship', context }}
          render={({ props }) => (
            <StixCoreRelationshipsExportsContent
              handleToggle={handleToggle.bind(this)}
              data={props}
              paginationOptions={paginationOptions}
              exportEntityType="stix-core-relationship"
              isOpen={open}
              context={context}
            />
          )}
        />
      </Drawer>
    );
  }
}

StixCoreRelationshipsExports.propTypes = {
  classes: PropTypes.object.isRequired,
  open: PropTypes.bool,
  handleToggle: PropTypes.func,
  paginationOptions: PropTypes.object,
  handleApplyListArgs: PropTypes.func,
  context: PropTypes.string,
};

export default compose(withStyles(styles))(StixCoreRelationshipsExports);
