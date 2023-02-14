import React, { FunctionComponent } from 'react';
import makeStyles from '@mui/styles/makeStyles';
import Drawer from '@mui/material/Drawer';
import { Theme } from '@mui/material/styles/createTheme';
import Typography from '@mui/material/Typography';
// import { useFormatter } from '../../components/i18n';

const useStyles = makeStyles < Theme >((theme) => ({
  drawerPaper: {
    minHeight: '100vh',
    width: 250,
    padding: '0 20px 20px 20px',
    display: 'flex',
    overflow: 'hidden',
    zIndex: 1100,
  },
  title: {
    marginTop: '100px',
  },
  listIcon: {
    marginRight: 0,
  },
  item: {
    padding: '0 0 0 6px',
  },
  itemField: {
    padding: '0 15px 0 15px',
  },
  toolbar: theme.mixins.toolbar,
}));

interface EntityDetailsRightsBarProps {
  selectedNodes: { id: string, value:string }[];
  open: boolean
  handleClose: () => void
}
const EntityDetailsRightsBar: FunctionComponent<EntityDetailsRightsBarProps> = ({ selectedNodes, open, handleClose }) => {
  const classes = useStyles();
  // const { t } = useFormatter();
  const entity = selectedNodes[0];
  console.log('entity:   ', entity);
  return (
    <Drawer
      open={open}
      variant="permanent"
      anchor="right"
      classes={{ paper: classes.drawerPaper }}
      onClose={handleClose}
    >
      {entity && <Typography variant="h6" classes={{ root: classes.title }}>
        {entity.id}
      </Typography>}
    </Drawer>
  );
};

export default EntityDetailsRightsBar;
