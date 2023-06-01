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
    width: '50%',
    position: 'fixed',
    transition: theme.transitions.create('width', {
      easing: theme.transitions.easing.sharp,
      duration: theme.transitions.duration.enteringScreen,
    }),
    padding: 0,
  },
});

class StixCoreRelationshipsExports extends Component {
  render() {
    const { classes, paginationOptions, open, handleToggle, context } = this.props;
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
