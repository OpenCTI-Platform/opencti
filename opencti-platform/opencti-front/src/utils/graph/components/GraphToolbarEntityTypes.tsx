import List from '@mui/material/List';
import ListItemText from '@mui/material/ListItemText';
import Popover from '@mui/material/Popover';
import React from 'react';
import { ListItemButton } from '@mui/material';
import { useFormatter } from '../../../components/i18n';
import { useGraphContext } from '../utils/GraphContext';

interface GraphToolbarEntityTypesProps {
  onClose: () => void
  onSelect: (entityType: string) => void
  anchorEl?: Element
}

const GraphToolbarEntityTypes = ({
  onClose,
  onSelect,
  anchorEl,
}: GraphToolbarEntityTypesProps) => {
  const { t_i18n } = useFormatter();
  const { stixCoreObjectTypes } = useGraphContext();

  return (
    <Popover
      open={!!anchorEl}
      anchorEl={anchorEl}
      onClose={onClose}
    >
      <List>
        {stixCoreObjectTypes.map((stixCoreObjectType) => (
          <ListItemButton
            dense
            key={stixCoreObjectType}
            onClick={() => onSelect(stixCoreObjectType)}
          >
            <ListItemText primary={t_i18n(`entity_${stixCoreObjectType}`)} />
          </ListItemButton>
        ))}
      </List>
    </Popover>
  );
};

export default GraphToolbarEntityTypes;
