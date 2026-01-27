import InputAdornment from '@mui/material/InputAdornment';
import IconButton from '@mui/material/IconButton';
import { PaletteOutlined } from '@mui/icons-material';
import Popover, { PopoverProps } from '@mui/material/Popover';
import MenuList from '@mui/material/MenuList';
import MenuItem from '@mui/material/MenuItem';
import Checkbox from '@mui/material/Checkbox';
import ListItemText from '@mui/material/ListItemText';
import React, { useState } from 'react';
import { useFormatter } from '../../../../components/i18n';
import useAttributes from '../../../../utils/hooks/useAttributes';
import { displayEntityTypeForTranslation } from '../../../../utils/String';

interface SearchScopeElementProps {
  name: string;
  disabled?: boolean;
  searchScope: Record<string, string[]>;
  setSearchScope: React.Dispatch<React.SetStateAction<Record<string, string[]>>>;
  availableRelationFilterTypes?: Record<string, string[]>;
}

const SearchScopeElement = ({
  name,
  disabled = false,
  searchScope,
  setSearchScope,
  availableRelationFilterTypes,
}: SearchScopeElementProps) => {
  const { t_i18n } = useFormatter();
  const [anchorElSearchScope, setAnchorElSearchScope] = useState<PopoverProps['anchorEl']>();
  const { stixCoreObjectTypes: entityTypes } = useAttributes();
  if (name === 'contextEntityId') {
    entityTypes.push('User');
    entityTypes.push('Group');
  }
  const entitiesTypes = entityTypes
    .filter((n) => (availableRelationFilterTypes && availableRelationFilterTypes[name]
      ? availableRelationFilterTypes[name].includes(n)
      : true))
    .map((n) => {
      return {
        label: t_i18n(displayEntityTypeForTranslation(n)),
        value: n,
        type: n,
      };
    })
    .sort((a, b) => a.label.localeCompare(b.label));
  const handleOpenSearchScope = (event: React.SyntheticEvent) => setAnchorElSearchScope(event.currentTarget);
  const handleCloseSearchScope = () => setAnchorElSearchScope(undefined);
  const handleToggleSearchScope = (key: string, value: string) => {
    setSearchScope((c) => ({
      ...c,
      [key]: (searchScope[key] || []).includes(value)
        ? searchScope[key].filter((n) => n !== value)
        : [...(searchScope[key] || []), value],
    }));
  };

  const color: 'secondary' | 'primary' = searchScope[name] && searchScope[name].length > 0
    ? 'secondary'
    : 'primary';

  return (
    <InputAdornment position="end" style={{ position: 'absolute', right: 5 }}>
      <IconButton disabled={disabled} onClick={handleOpenSearchScope} size="small" edge="end">
        <PaletteOutlined fontSize="small" color={disabled ? undefined : color} />
      </IconButton>
      <Popover
        sx={{
          '& .MuiPaper-root': {
            width: 300,
            padding: 0,
          },
        }}
        open={Boolean(anchorElSearchScope)}
        anchorEl={anchorElSearchScope}
        onClose={() => handleCloseSearchScope()}
        anchorOrigin={{
          vertical: 'center',
          horizontal: 'right',
        }}
        transformOrigin={{
          vertical: 'center',
          horizontal: 'left',
        }}
        elevation={8}
      >
        <MenuList dense={true}>
          {entitiesTypes.map((entityType) => (
            <MenuItem
              key={entityType.value}
              value={entityType.value}
              dense={true}
              onClick={() => handleToggleSearchScope(name, entityType.value)}
            >
              <Checkbox
                size="small"
                checked={(searchScope[name] || []).includes(entityType.value)}
              />
              <ListItemText primary={entityType.label} />
            </MenuItem>
          ))}
        </MenuList>
      </Popover>
    </InputAdornment>
  );
};

export default SearchScopeElement;
