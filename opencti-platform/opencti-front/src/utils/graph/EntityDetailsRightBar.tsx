import React, { FunctionComponent } from 'react';
import makeStyles from '@mui/styles/makeStyles';
import Drawer from '@mui/material/Drawer';
import { Theme } from '@mui/material/styles/createTheme';
import List from '@mui/material/List';
import ListSubheader from '@mui/material/ListSubheader';
import ListItem from '@mui/material/ListItem';
import ListItemText from '@mui/material/ListItemText';
import { useFormatter } from '../../components/i18n';

const useStyles = makeStyles < Theme >((theme) => ({
  drawerPaper: {
    minHeight: '100vh',
    width: 250,
    padding: '0 20px 20px 20px',
    display: 'flex',
    zIndex: 1100,
  },
  title: {
    marginTop: '100px',
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
  const { t } = useFormatter();
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
      <List classes={{ root: classes.title }}
        subheader={
          <ListSubheader component="div">
            {t('Entity List')}
          </ListSubheader>
        }
      >
        {selectedNodes.map((node) => (
          <ListItem
            classes={{ root: classes.item }}
          >
            <ListItemText primary={node.id} />
          </ListItem>
        ))}
      </List>
    </Drawer>
  );
};

export default EntityDetailsRightsBar;
