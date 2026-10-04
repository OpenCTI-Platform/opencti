import React, { Fragment } from 'react';
import List from '@mui/material/List';
import ListSubheader from '@mui/material/ListSubheader';
import Popover from '@mui/material/Popover';
import { ListItemButton } from '@mui/material';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import { Checkbox } from '@filigran/design-system';

interface GraphToolbarOptionsListProps<T> {
  onClose: () => void;
  onSelect: (o: T) => void;
  options: T[];
  getOptionKey: (o: T) => string;
  getOptionText: (o: T) => string;
  /** Heading of the part of the list an option belongs to; options of a part are contiguous. */
  getOptionSection?: (o: T) => string | undefined;
  isOptionSelected?: (o: T) => boolean;
  anchorEl?: Element;
  isMultiple?: boolean;
}

function GraphToolbarOptionsList<T>({
  onClose,
  onSelect,
  options,
  getOptionKey,
  getOptionText,
  getOptionSection = () => undefined,
  anchorEl,
  isMultiple = false,
  isOptionSelected = () => false,
}: GraphToolbarOptionsListProps<T>) {
  return (
    <Popover
      open={!!anchorEl}
      anchorEl={anchorEl}
      onClose={onClose}
      anchorOrigin={{ vertical: 'top', horizontal: 'left' }}
      transformOrigin={{ vertical: 'bottom', horizontal: 'left' }}
      slotProps={{ paper: { style: { maxHeight: '60vh' } } }}
    >
      <List>
        {options.map((option, index) => {
          const section = getOptionSection(option);
          const opensSection = section && (index === 0 || getOptionSection(options[index - 1]) !== section);
          return (
            <Fragment key={getOptionKey(option)}>
              {opensSection && <ListSubheader disableSticky style={{ lineHeight: '32px', background: 'transparent' }}>{section}</ListSubheader>}
              <ListItemButton
                dense
                onClick={() => onSelect(option)}
              >
                {isMultiple && (
                  <ListItemIcon sx={{ minWidth: 0, marginRight: 1, pointerEvents: 'none' }}>
                    <Checkbox
                      aria-label={getOptionText(option)}
                      className="py-1"
                      checked={isOptionSelected(option)}
                    />
                  </ListItemIcon>
                )}
                <ListItemText primary={getOptionText(option)} />
              </ListItemButton>
            </Fragment>
          );
        })}
      </List>
    </Popover>
  );
}

export default GraphToolbarOptionsList;
