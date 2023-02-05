import React from 'react';
import Drawer from '@mui/material/Drawer';
import makeStyles from '@mui/styles/makeStyles';
import { QueryRenderer } from '../../../../relay/environment';
import StixCoreObjectsExportsContent, {
  stixCoreObjectsExportsContentQuery,
} from './StixCoreObjectsExportsContent';

const useStyles = makeStyles((theme) => ({
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
}));

const StixCoreObjectsExports = ({
  exportEntityType,
  paginationOptions,
  open,
  handleToggle,
  context,
}) => {
  const classes = useStyles();
  return (
    <Drawer
      open={open}
      anchor="right"
      sx={{ zIndex: 1202 }}
      elevation={1}
      classes={{ paper: classes.drawerPaper }}
      onClose={handleToggle}
    >
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
};

export default StixCoreObjectsExports;
