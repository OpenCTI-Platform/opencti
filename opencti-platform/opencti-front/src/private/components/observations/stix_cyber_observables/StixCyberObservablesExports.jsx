import React from 'react';
import * as PropTypes from 'prop-types';
import withStyles from '@mui/styles/withStyles';
import Slide from '@mui/material/Slide';
import { QueryRenderer } from '../../../../relay/environment';
import StixCyberObservablesExportsContent, { stixCyberObservablesExportsContentQuery } from './StixCyberObservablesExportsContent';
import Drawer from '@components/common/drawer/Drawer';
import { useFormatter } from '../../../../components/i18n';

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

const StixCyberObservablesExports = (props) => {
  const { t_i18n } = useFormatter();
  const { paginationOptions, open, handleToggle, exportContext } = props;
  return (
    <Drawer
      open={open}
      elevation={1}
      onClose={handleToggle}
      title={t_i18n('Exports list')}
      size="medium"
    >
      <QueryRenderer
        query={stixCyberObservablesExportsContentQuery}
        variables={{ count: 25, exportContext }}
        render={({ props }) => (
          <StixCyberObservablesExportsContent
            handleToggle={handleToggle}
            data={props}
            paginationOptions={paginationOptions}
            isOpen={open}
            exportContext={exportContext}
          />
        )}
      />
    </Drawer>
  );
};

StixCyberObservablesExports.propTypes = {
  classes: PropTypes.object.isRequired,
  open: PropTypes.bool,
  handleToggle: PropTypes.func,
  paginationOptions: PropTypes.object,
  handleApplyListArgs: PropTypes.func,
  exportContext: PropTypes.object,
};

export default withStyles(styles)(StixCyberObservablesExports);
