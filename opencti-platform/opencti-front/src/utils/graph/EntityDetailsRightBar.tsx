import React, { FunctionComponent, useState } from 'react';
import makeStyles from '@mui/styles/makeStyles';
import Drawer from '@mui/material/Drawer';
import { Theme } from '@mui/material/styles/createTheme';
import List from '@mui/material/List';
import ListSubheader from '@mui/material/ListSubheader';
import ListItem from '@mui/material/ListItem';
import ListItemText from '@mui/material/ListItemText';
import Tooltip from '@mui/material/Tooltip';
import IconButton from '@mui/material/IconButton';
import { Link } from 'react-router-dom';
import { InfoOutlined } from '@mui/icons-material';
import { useFormatter } from '../../components/i18n';
import { resolveLink } from '../Entity';

const useStyles = makeStyles < Theme >((theme) => ({
  drawerPaper: {
    variant: 'persistent',
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

interface selectedNode {
  id: string
  name: string
  description: string
  parent_types: string
  relationship_type: string
  fromType: string
  fromId: string
  entity_type: string

}
interface EntityDetailsRightsBarProps {
  selectedNodes: selectedNode[];
  open: boolean
  handleClose?: () => void
}
const EntityDetailsRightsBar: FunctionComponent<EntityDetailsRightsBarProps> = ({ selectedNodes, open, handleClose }) => {
  const classes = useStyles();
  const { t } = useFormatter();

  const [controlOpen, setControlOpen] = useState<boolean>(open ?? false);
  const handleControlClose = () => setControlOpen(false);
  console.log('entity:   ', selectedNodes[0]);

  const viewLink = () => {
    if (
      !selectedNodes[0].parent_types.includes(
        'stix-cyber-observable-relationship',
      )
      && selectedNodes[0].relationship_type
    ) {
      return `${resolveLink(selectedNodes[0].fromType)}/${
        selectedNodes[0].fromId
      }/knowledge/relations/${selectedNodes[0].id}`;
    }
    return `${resolveLink(selectedNodes[0].entity_type)}/${
      selectedNodes[0].id
    }`;
  };

  return (
    <Drawer
      open={handleClose ? open : controlOpen}
      variant="permanent"
      anchor="right"
      classes={{ paper: classes.drawerPaper }}
      onClose={handleClose ?? handleControlClose }
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
            <Tooltip title={t('View the item')}>
                  <span>
                    <IconButton
                      color="primary"
                      component={Link}
                      target="_blank"
                      to={viewLink}
                      disabled={!viewLink}
                      size="large"
                    >
                      <InfoOutlined />
                    </IconButton>
                  </span>
            </Tooltip>
          </ListItem>
        ))}
      </List>
    </Drawer>
  );
};

export default EntityDetailsRightsBar;
