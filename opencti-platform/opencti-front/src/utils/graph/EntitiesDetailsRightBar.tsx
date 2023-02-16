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
  parent_types: string
  relationship_type: string
  fromType: string
  fromId: string
  entity_type: string
}
interface EntityDetailsRightsBarProps {
  selectedNodes: SelectedNode[];
  open: boolean
  handleClose?: () => void
}
const EntitiesDetailsRightsBar: FunctionComponent<EntityDetailsRightsBarProps> = ({ selectedNodes, open, handleClose }) => {
  const classes = useStyles();
  const { t } = useFormatter();

  const [controlOpen, setControlOpen] = useState<boolean>(open ?? false);
  const handleControlClose = () => setControlOpen(false);

  const [selectedNodeId, setSelectedNodeId] = useState<string>(selectedNodes[0].id);
  const handleSelectNode = (event: SelectChangeEvent<string>) => {
    setSelectedNodeId(event.target.value);
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
        <InputLabel id="entityField">
          {t('Selected entities')}
        </InputLabel>
        <Select
          labelId="entityField"
          fullWidth={true}
          onChange={(event: SelectChangeEvent<string>) => handleSelectNode(event)}
        >
          {selectedNodes.map((node) => (
            <MenuItem key={node.id} value={node.id}>
              {node.label}
            </MenuItem>
          ))}
        </Select>
      </FormControl>
        <EntityDetails
          nodeId={selectedNodeId}
        />
    </Drawer>
  );
};
export default EntitiesDetailsRightsBar;
