import InputAdornment from '@mui/material/InputAdornment';
import IconButton from '@mui/material/IconButton';
import { PaletteOutlined } from '@mui/icons-material';
import Popover from '@mui/material/Popover';
import MenuList from '@mui/material/MenuList';
import MenuItem from '@mui/material/MenuItem';
import Checkbox from '@mui/material/Checkbox';
import ListItemText from '@mui/material/ListItemText';
import React, { useState } from 'react';
import makeStyles from '@mui/styles/makeStyles';
import { useFormatter } from '../../../../components/i18n';
import useAttributes from '../../../../utils/hooks/useAttributes';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles({
  container2: {
    width: 300,
    padding: 0,
  },
});

const SearchScopeElement = ({
  name,
  searchScope,
  setSearchScope,
  availableRelationFilterTypes,
}) => {
  const { t_i18n } = useFormatter();
  const classes = useStyles();
  const [anchorElSearchScope, setAnchorElSearchScope] = useState();
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
        label: t_i18n(n.toString()[0] === n.toString()[0].toUpperCase()
          ? `entity_${n.toString()}`
          : `relationship_${n.toString()}`),
        value: n,
        type: n,
      };
    })
    .sort((a, b) => a.label.localeCompare(b.label));
  const handleOpenSearchScope = (event) => setAnchorElSearchScope(event.currentTarget);
  const handleCloseSearchScope = () => setAnchorElSearchScope(undefined);
  const handleToggleSearchScope = (key, value) => {
    setSearchScope((c) => ({
      ...c,
      [key]: (searchScope[key] || []).includes(value)
        ? searchScope[key].filter((n) => n !== value)
        : [...(searchScope[key] || []), value],
    }));
  };
  return (
    <InputAdornment position="end" style={{ position: 'absolute', right: 5 }}>
      <IconButton onClick={handleOpenSearchScope} size="small" edge="end">
        <PaletteOutlined
          fontSize="small"
          color={
            searchScope[name] && searchScope[name].length > 0
              ? 'secondary'
              : 'primary'
          }
        />
      </IconButton>
      <Popover
        classes={{ paper: classes.container2 }}
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
