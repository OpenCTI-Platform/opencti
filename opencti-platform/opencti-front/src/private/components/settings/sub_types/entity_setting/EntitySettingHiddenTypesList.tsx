import React, { FunctionComponent } from 'react';
import List from '@mui/material/List';
import { Link } from 'react-router-dom';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import { Box, ListItemButton } from '@mui/material';
import ItemIcon from '../../../../../components/ItemIcon';
import FieldOrEmpty from '../../../../../components/FieldOrEmpty';
import Label from '../../../../../components/common/label/Label';

export interface Entity {
  readonly id: string;
  readonly name: string;
  readonly default_hidden_types?: ReadonlyArray<string> | null;
}

const computeHiddenEntities = (nodes: Array<Entity | undefined>, targetType: string) => {
  const result: Entity[] = [];
  nodes.forEach((node) => {
    if (node?.default_hidden_types?.includes(targetType)) {
      result.push(node);
    }
  });
  return result;
};

const EntitySettingHiddenTypesList: FunctionComponent<{
  targetType: string;
  nodes: Array<Entity | undefined>;
  label: string;
  link: string;
  entityType: string;
}> = ({
  targetType,
  nodes,
  label,
  link,
  entityType,
}) => {
  const hiddenEntities = computeHiddenEntities(nodes, targetType);
  return (
    <Box sx={{ marginTop: 2 }}>
      <Label>
        {label}
      </Label>
      <List style={{ paddingTop: 0 }}>
        <FieldOrEmpty source={hiddenEntities}>
          {hiddenEntities.map((hiddenEntity) => (
            <ListItemButton
              key={hiddenEntity.id}
              dense={true}
              divider={true}
              component={Link}
              to={`${link}${hiddenEntity.id}`}
            >
              <ListItemIcon>
                <ItemIcon type={entityType} />
              </ListItemIcon>
              <ListItemText primary={hiddenEntity.name} />
            </ListItemButton>
          ))}
        </FieldOrEmpty>
      </List>
    </Box>
  );
};

export default EntitySettingHiddenTypesList;
