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

const useStyles = makeStyles<Theme>((theme) => ({
  drawerPaper: {
    width: 'auto',
    maxWidth: '400px',
    padding: '20px 20px 20px 20px',
    position: 'absolute',
    zIndex: 900,
  },
  formControl: {
    width: '100%',
    marginTop: '10px',
  },
  label: {
    backgroundColor: theme.palette.background.paper,
  },
}));

export interface SelectedEntity {
  id: string
  label: string
  relationship_type?: string
  entity_type: string
  source? : SelectedEntity
  target?: SelectedEntity
  fromId?: string
  fromType?: string
  toId?: string
  toType?: string
}

interface EntityDetailsRightsBarProps {
  selectedEntities: SelectedEntity[];
}
const EntitiesDetailsRightsBar: FunctionComponent<
EntityDetailsRightsBarProps
> = ({ selectedEntities }) => {
  const classes = useStyles();

  const uniqSelectedEntities: SelectedEntity[] = selectedEntities.filter(
    (item, index) => {
      return (
        selectedEntities.findIndex((entity) => entity.id === item.id) === index
      );
    },
  );
  const [selectedEntity, setSelectedEntity] = useState<SelectedEntity>(
    uniqSelectedEntities[0],
  );
  useEffect(() => {
    if (uniqSelectedEntities[0] !== selectedEntity) {
      setSelectedEntity(uniqSelectedEntities[0]);
    }
  }, [selectedEntities]);
  const handleSelectEntity = (event: SelectChangeEvent<SelectedEntity>) => {
    const { value } = event.target;
    const entity = selectedEntities.find((el) => el.id === value);
    if (!entity) {
      setSelectedEntity(uniqSelectedEntities[0]);
    } else {
      setSelectedEntity(entity);
    }
  };
  const selectInputLabel = () => {
    if (!selectedEntity.relationship_type) {
      return (selectedEntity.label.length > 1 ? selectedEntity.label : selectedEntity.entity_type);
    }
    if (selectedEntity.source && selectedEntity.target) {
      const source = selectedEntity.source.label;
      const target = selectedEntity.target.label;
      return (`${source} to ${target}`);
    }
    if (selectedEntity.fromType && selectedEntity.toType) {
      const source = selectedEntity.fromType;
      const target = selectedEntity.toType;
      return (`${source} to ${target}`);
    }
    return (selectedEntity.label.length > 1 ? selectedEntity.label : selectedEntity.entity_type);
  };

  return (
    <Drawer
      open={true}
      variant="permanent"
      anchor="right"
      classes={{ paper: classes.drawerPaper }}
    >
      <div className={classes.toolbar} />
      <FormControl className={classes.formControl} fullWidth={true}>
        <InputLabel id="entityField" className={classes.label}>
          {selectInputLabel()}
        </InputLabel>
        <Select
          labelId="entityField"
          fullWidth={true}
          onChange={handleSelectEntity}
        >
          {uniqSelectedEntities.map((entity) => (
            <MenuItem key={entity.id} value={entity.id}>
              {entity.label.length > 1 ? entity.label : entity.entity_type}
            </MenuItem>
          ))}
        </Select>
      </FormControl>
      {selectedEntity.relationship_type ? (
        <RelationshipDetails relation={selectedEntity} />
      ) : (
        <EntityDetails entity={selectedEntity} />
      )}
    </Drawer>
  );
};
export default EntitiesDetailsRightsBar;
