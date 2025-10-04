import React, { FunctionComponent } from 'react';
import { Link } from 'react-router-dom';
import ItemIcon from '../../../../../components/ItemIcon';
import FieldOrEmpty from '../../../../../components/FieldOrEmpty';
import { List, ListItemButton, ListItemIcon, ListItemText, Typography } from '@components';

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
  targetType: string
  nodes: Array<Entity | undefined>
  label: string
  link: string
  entityType: string
}> = ({
  targetType,
  nodes,
  label,
  link,
  entityType,
}) => {
  const hiddenEntities = computeHiddenEntities(nodes, targetType);
  return (
    <div style={{ marginTop: 20 }}>
      <Typography variant="h3" gutterBottom={true}>
        {label}
      </Typography>
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
    </div>
  );
};

export default EntitySettingHiddenTypesList;
