import React, { useState, useRef, useEffect } from 'react';
import {
  Button,
  Menu,
  MenuItem,
  Box,
  Typography,
} from '@mui/material';
import { ChevronDown24Regular as ChevronDownIcon } from '@fluentui/react-icons';
import { FilterValue } from './DashboardFilterBar';

interface FilterDropdownProps {
  label: string;
  value: FilterValue | null;
  options: FilterValue[];
  onChange: (value: FilterValue) => void;
}

const FilterDropdown: React.FC<FilterDropdownProps> = ({
  label,
  value,
  options,
  onChange,
}) => {
  const [anchorEl, setAnchorEl] = useState<null | HTMLElement>(null);
  const buttonRef = useRef<HTMLButtonElement>(null);
  const open = Boolean(anchorEl);

  const handleClick = (event: React.MouseEvent<HTMLElement>) => {
    setAnchorEl(event.currentTarget);
  };

  const handleClose = () => {
    setAnchorEl(null);
  };

  const handleSelect = (option: FilterValue) => {
    onChange(option);
    handleClose();
  };

  return (
    <>
      <Button
        ref={buttonRef}
        variant="outlined"
        onClick={handleClick}
        startIcon={<ChevronDownIcon fontSize="small" />}
        sx={{
          textTransform: 'none',
          minWidth: 'auto',
          whiteSpace: 'nowrap',
          color: 'text.primary',
          borderColor: 'divider',
          '& .MuiButton-startIcon': {
            marginLeft: 0.5,
          },
          '&:hover': {
            borderColor: 'primary.main',
            backgroundColor: 'action.hover',
          },
        }}
      >
        {value?.label || label}
      </Button>
      <Menu
        anchorEl={anchorEl}
        open={open}
        onClose={handleClose}
        anchorOrigin={{
          vertical: 'bottom',
          horizontal: 'right',
        }}
        transformOrigin={{
          vertical: 'top',
          horizontal: 'right',
        }}
        PaperProps={{
          sx: {
            minWidth: buttonRef.current?.offsetWidth || 200,
            maxHeight: 300,
          },
        }}
      >
        {options.map((option) => (
          <MenuItem
            key={option.id}
            onClick={() => handleSelect(option)}
            selected={value?.id === option.id}
            sx={{
              '&.Mui-selected': {
                backgroundColor: 'primary.lighter',
                '&:hover': {
                  backgroundColor: 'primary.light',
                },
              },
            }}
          >
            <Typography variant="body2">{option.label}</Typography>
          </MenuItem>
        ))}
      </Menu>
    </>
  );
};

export default FilterDropdown;
