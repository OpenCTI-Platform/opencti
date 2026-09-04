import List from '@mui/material/List';
import Popover from '@mui/material/Popover';
import { ListItemButton } from '@mui/material';
import ListItemIcon from '@mui/material/ListItemIcon';
import { Checkbox } from '@filigran/design-system';

interface GraphToolbarOptionsListProps<T> {
  onClose: () => void;
  onSelect: (o: T) => void;
  options: T[];
  getOptionKey: (o: T) => string;
  getOptionText: (o: T) => string;
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
  anchorEl,
  isMultiple = false,
  isOptionSelected = () => false,
}: GraphToolbarOptionsListProps<T>) {
  return (
    <Popover
      open={!!anchorEl}
      anchorEl={anchorEl}
      onClose={onClose}
    >
      <List>
        {options.map((option) => (
          <ListItemButton
            dense
            key={getOptionKey(option)}
            onClick={() => onSelect(option)}
          >
            {isMultiple && (
              <ListItemIcon sx={{ minWidth: 0 }}>
                <Checkbox
                  aria-label={getOptionText(option)}
                  label={getOptionText(option)}
                  className="py-1"
                  checked={isOptionSelected(option)}
                />
              </ListItemIcon>
            )}
          </ListItemButton>
        ))}
      </List>
    </Popover>
  );
}

export default GraphToolbarOptionsList;
