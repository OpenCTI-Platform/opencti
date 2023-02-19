import React, { FunctionComponent, useState } from 'react';
import makeStyles from '@mui/styles/makeStyles';
import Drawer from '@mui/material/Drawer';
import { Theme } from '@mui/material/styles/createTheme';
import FormControl from '@mui/material/FormControl';
import InputLabel from '@mui/material/InputLabel';
import Select, { SelectChangeEvent } from '@mui/material/Select';
import MenuItem from '@mui/material/MenuItem';
import { useFormatter } from '../../components/i18n';
import EntityDetails from './EntityDetails';

const useStyles = makeStyles < Theme >((theme) => ({
  drawerPaper: {
    minHeight: '100vh',
    width: 250,
    padding: '0 20px 20px 20px',
    position: 'fixed',
    zIndex: 900,
  },
  formControl: {
    width: '100%',
    marginTop: '20px',
  },
  toolbar: theme.mixins.toolbar,
}));

export interface SelectedNode {
  id: string
  name: string
  label: string
  description: string
  parent_types: string[]
  relationship_type: string
  fromType: string
  fromId: string
  entity_type: string
}

export interface SelectedLink {
  id: string
  name: string
  label: string
  source: SelectedNode
  source_id: string
  parent_types: string[]
  relationship_type: string
  target: SelectedNode
  target_id: string
  entity_type: string
}
interface EntityDetailsRightsBarProps {
  selectedNodes: SelectedNode[];
  selectedLinks:SelectedLink[]
  open: boolean
  handleClose?: () => void
}
const EntitiesDetailsRightsBar: FunctionComponent<EntityDetailsRightsBarProps> = ({ selectedNodes, selectedLinks, open, handleClose }) => {
  const classes = useStyles();
  const { t } = useFormatter();
  const nodesAndLinks: Array<SelectedLink | SelectedNode> = [...selectedLinks, ...selectedNodes];

  const [controlOpen, setControlOpen] = useState<boolean>(open ?? false);
  const handleControlClose = () => setControlOpen(false);

  const [selectedEntity, setSelectedEntity] = useState<SelectedLink | SelectedNode>(nodesAndLinks[0]);
  const handleSelectNode = (event: SelectChangeEvent<SelectedLink | SelectedNode>) => {
    setSelectedEntity(event.target);
  };

  const fillSelectLabel = () => {
    if (nodesAndLinks.length > 1) {
      return (
        <InputLabel id="entityField">
          {t('Selected entities')}
        </InputLabel>
      );
    }
    return (
      <InputLabel id="entityField">
        {nodesAndLinks[0].label}
      </InputLabel>
    );
  };

  return (
    <Drawer
      open={handleClose ? open : controlOpen}
      variant="permanent"
      anchor="right"
      classes={{ paper: classes.drawerPaper }}
      onClose={handleClose ?? handleControlClose }
    >
      <div className={classes.toolbar} />
      <FormControl
        className={classes.formControl}
        fullWidth={true}
      >
        {fillSelectLabel()}
        <Select
          labelId="entityField"
          fullWidth={true}
          onChange={(event: SelectChangeEvent<SelectedNode>) => handleSelectNode(event)}
        >
          {nodesAndLinks.map((nodeOrLink) => (
            <MenuItem key={nodeOrLink.id} value={nodeOrLink.id}>
              {nodeOrLink.label}
            </MenuItem>
          ))}
        </Select>
      </FormControl>
        <EntityDetails
          entity={selectedEntity}
        />
    </Drawer>
  );
};
export default EntitiesDetailsRightsBar;
