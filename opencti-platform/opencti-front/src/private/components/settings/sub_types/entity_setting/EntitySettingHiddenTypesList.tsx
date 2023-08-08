import React, { FunctionComponent } from 'react';
import Typography from '@mui/material/Typography';
import List from '@mui/material/List';
import { Link } from 'react-router-dom';
import ListItemIcon from '@mui/material/ListItemIcon';
import { SecurityOutlined } from '@mui/icons-material';
import ListItemText from '@mui/material/ListItemText';
import { ListItemButton } from '@mui/material';
import { isEmptyField } from '../../../../../utils/utils';

interface Entity {
  readonly id: string;
  readonly name: string;
  readonly default_hidden_types: ReadonlyArray<string> | null;
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
}> = ({
  targetType,
  nodes,
  label,
  link,
}) => {
  const hiddenEntities = computeHiddenEntities(nodes, targetType);
  return (
    <div style={{ marginTop: 20 }}>
      <Typography variant="h3" gutterBottom={true}>
        {label}
      </Typography>
      <List style={{ paddingTop: 0 }}>
        {isEmptyField(hiddenEntities) ? <div>{'-'}</div> : (
          <>
            {hiddenEntities.map((hiddenEntity) => (
              <ListItemButton
                key={hiddenEntity.id}
                dense={true}
                divider={true}
                component={Link}
                to={`${link}${hiddenEntity.id}`}
              >
                <ListItemIcon>
                  <SecurityOutlined color="primary" />
                </ListItemIcon>
                <ListItemText primary={hiddenEntity.name} />
              </ListItemButton>
            ))}
          </>
        )}
      </List>
    </div>
  );
};

export default EntitySettingHiddenTypesList;
