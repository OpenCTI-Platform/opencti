import List from '@mui/material/List';
import { ListItemButton } from '@mui/material';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import React from 'react';
import ItemIcon from '../../../../../components/ItemIcon';
import { useFormatter } from '../../../../../components/i18n';

interface PlaybookSelectComponentProps {
  components: unknown[]
  onSelect: (componentId: string) => void
}

const PlaybookSelectComponent = ({
  components,
  onSelect,
}: PlaybookSelectComponentProps) => {
  const { t_i18n } = useFormatter();
  // const entryComponents =

  return (
    <div>
      <List>
        {components.map((component) => {
          return (
            <ListItemButton
              key={component.id}
              divider={true}
              onClick={() => onSelect(component.id)}
            >
              <ListItemIcon>
                <ItemIcon type={component.icon}/>
              </ListItemIcon>
              <ListItemText
                primary={t_i18n(component.name)}
                secondary={t_i18n(component.description)}
              />
            </ListItemButton>
          );
        })}
      </List>
    </div>
  );
};

export default PlaybookSelectComponent;
