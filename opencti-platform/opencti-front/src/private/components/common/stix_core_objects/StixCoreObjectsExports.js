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
    width: 310,
    padding: '0 0 20px 0',
    overflowX: 'hidden',
    zIndex: 1200,
  },
  toolbar: theme.mixins.toolbar,
}));

const StixCoreObjectsExports = ({
  exportEntityType,
  paginationOptions,
  open,
  handleToggle,
  context,
  variant,
}) => {
  const classes = useStyles();
  return (
    <Drawer
      variant={variant || 'persistent'}
      open={open}
      anchor="right"
      elevation={1}
      sx={{ zIndex: 1202 }}
      classes={{ paper: classes.drawerPaper }}
      onClose={handleToggle}
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
};

export default StixCoreObjectsExports;
