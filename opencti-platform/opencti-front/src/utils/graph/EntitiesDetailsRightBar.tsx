import React, { FunctionComponent, useEffect, useState } from 'react';
import makeStyles from '@mui/styles/makeStyles';
import Drawer from '@mui/material/Drawer';
import { Theme } from '@mui/material/styles/createTheme';
import FormControl from '@mui/material/FormControl';
import InputLabel from '@mui/material/InputLabel';
import Select, { SelectChangeEvent } from '@mui/material/Select';
import MenuItem from '@mui/material/MenuItem';
import EntityDetails from './EntityDetails';
import RelationshipDetails from './RelationshipDetails';

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
  label: {
    backgroundColor: '#001e3c',
  },
  toolbar: theme.mixins.toolbar,
}));

export interface SelectedEntity {
  id: string
  label: string
  relationship_type?: string
}

interface EntityDetailsRightsBarProps {
  selectedEntities: SelectedEntity[]
}
const EntitiesDetailsRightsBar: FunctionComponent<EntityDetailsRightsBarProps> = ({ selectedEntities }) => {
  const classes = useStyles();

  const [selectedEntity, setSelectedEntity] = useState<SelectedEntity>(selectedEntities[0]);
  useEffect(() => {
    if (selectedEntities[0] !== selectedEntity) {
      setSelectedEntity(selectedEntities[0]);
    }
  }, [selectedEntities[0].id]);
  const handleSelectEntity = (event: SelectChangeEvent<SelectedEntity>) => {
    const { value } = event.target;
    const entity = selectedEntities.find((el) => (el.id === value));
    if (entity === undefined) {
      setSelectedEntity(selectedEntities[0]);
    }
    if (entity) {
      setSelectedEntity(entity);
    }
  };

  return (
    <Drawer
      open={true}
      variant="permanent"
      anchor="right"
      classes={{ paper: classes.drawerPaper }}
    >
      <div className={classes.toolbar} />
      <FormControl
        className={classes.formControl}
        fullWidth={true}
      >
        <InputLabel id="entityField" className={classes.label}>
          {selectedEntities[0].label}
        </InputLabel>
        <Select
          labelId="entityField"
          fullWidth={true}
          onChange={handleSelectEntity}
        >
          {selectedEntities.map((entity) => (
            <MenuItem key={entity.id} value={entity.id}>
              {entity.label}
            </MenuItem>
          ))}
        </Select>
      </FormControl>
        {selectedEntity.relationship_type
          ? <RelationshipDetails
          relation={selectedEntity}
            />
          : <EntityDetails
          entity={selectedEntity}
            />}
    </Drawer>
  );
};
export default EntitiesDetailsRightsBar;
