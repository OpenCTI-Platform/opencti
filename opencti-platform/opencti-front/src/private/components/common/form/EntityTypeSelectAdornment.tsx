import InputAdornment from '@mui/material/InputAdornment';
import IconButton from '@common/button/IconButton';
import { PaletteOutlined } from '@mui/icons-material';
import Popover from '@mui/material/Popover';
import MenuList from '@mui/material/MenuList';
import MenuItem from '@mui/material/MenuItem';
import Checkbox from '@mui/material/Checkbox';
import ListItemText from '@mui/material/ListItemText';
import React, { useState } from 'react';
import useAttributes from '../../../../utils/hooks/useAttributes';
import { useEntityTypeDisplayName } from '../../../../utils/hooks/useEntityTypeDisplayName';

interface EntityTypeSelectAdornmentProps {
  disabled?: boolean;
  value: string[];
  onChange: (val: string[]) => void;
  entityTypes?: string[];
}

const EntityTypeSelectAdornment = ({
  disabled,
  value,
  onChange,
  entityTypes,
}: EntityTypeSelectAdornmentProps) => {
  const entityTypeDisplayName = useEntityTypeDisplayName();
  const { stixCoreObjectTypes } = useAttributes();
  const [anchorButton, setAnchorButton] = useState<HTMLButtonElement>();

  const options = (entityTypes ?? stixCoreObjectTypes).map((n) => ({
    label: entityLabel(n),
    value: n,
  }));

  const toggleEntityType = (entityType: string) => {
    const newValue = value.includes(entityType)
      ? value.filter((e) => e !== entityType)
      : [...value, entityType];
    onChange(newValue);
  };

  return (
    <InputAdornment position="end" style={{ position: 'absolute', right: 5 }}>
      <IconButton
        disabled={disabled}
        onClick={(e) => setAnchorButton(e.currentTarget)}
        size="small"
        // edge="end"
      >
        <PaletteOutlined
          fontSize="small"
          color={value.length > 0 ? 'secondary' : 'primary'}
        />
      </IconButton>
      <Popover
        elevation={8}
        open={Boolean(anchorButton)}
        anchorEl={anchorButton}
        onClose={() => setAnchorButton(undefined)}
        anchorOrigin={{
          vertical: 'center',
          horizontal: 'right',
        }}
        transformOrigin={{
          vertical: 'center',
          horizontal: 'left',
        }}
      >
        <MenuList dense>
          {options.map((entityType) => (
            <MenuItem
              dense
              key={entityType.value}
              value={entityType.value}
              onClick={() => toggleEntityType(entityType.value)}
            >
              <Checkbox
                size="small"
                checked={value.includes(entityType.value)}
              />
              <ListItemText primary={entityType.label} />
            </MenuItem>
          ))}
        </MenuList>
      </Popover>
    </InputAdornment>
  );
};

export default EntityTypeSelectAdornment;
