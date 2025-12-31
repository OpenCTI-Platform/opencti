import React, { useState } from 'react';
import {
  Box,
  Typography,
  Paper,
  Popover,
  List,
  ListItem,
  ListItemText,
  Divider,
  IconButton,
} from '@mui/material';
import {
  FilterList,
  MoreVert,
} from '@mui/icons-material';
import { useFormatter } from '../../../components/i18n';

interface FilterItem {
  id: string;
  name: string;
  label: string;
}

interface FilterPopoverProps {
  open: boolean;
  anchorEl: HTMLElement | null;
  onClose: () => void;
  width: number;
  title: string;
  filters: FilterItem[];
  onSelectFilter: (filterName: string) => void;
}

const FilterPopover = ({
  open,
  anchorEl,
  onClose,
  width,
  title,
  filters,
  onSelectFilter,
}: FilterPopoverProps) => {
  const { t_i18n } = useFormatter();
  const [hoveredItemId, setHoveredItemId] = useState<string | null>(null);

  return (
    <Popover
      open={open}
      anchorEl={anchorEl}
      onClose={onClose}
      anchorOrigin={{
        vertical: 'bottom',
        horizontal: 'left',
      }}
      transformOrigin={{
        vertical: 'top',
        horizontal: 'left',
      }}
      sx={{
        marginTop: 1,
      }}
      PaperProps={{
        sx: {
          width,
          maxWidth: '90vw',
        },
      }}
    >
      <Paper sx={{ width: '100%' }}>
        <Box sx={{ padding: 2 }}>
          <Typography
            variant="subtitle1"
            sx={{
              fontWeight: 600,
              marginBottom: 1.5,
            }}
          >
            {title}
          </Typography>
          <List dense sx={{ padding: 0 }}>
            {filters.map((filter) => {
              const isHovered = hoveredItemId === filter.id;
              return (
                <ListItem
                  key={filter.id}
                  component="button"
                  onClick={() => onSelectFilter(filter.name)}
                  onMouseEnter={() => setHoveredItemId(filter.id)}
                  onMouseLeave={() => setHoveredItemId(null)}
                  sx={{
                    borderRadius: 1,
                    marginBottom: 0.5,
                    cursor: 'pointer',
                    backgroundColor: isHovered ? '#E3F2FD' : 'rgba(0, 0, 0, 0.02)',
                    border: isHovered ? '1px solid #2196F3' : '1px solid rgba(0, 0, 0, 0.05)',
                    paddingTop: 1.2,
                    paddingBottom: 1.2,
                    minHeight: 36,
                  }}
                >
                  <Box sx={{ display: 'flex', alignItems: 'center', marginRight: 1 }}>
                    <FilterList fontSize="small" sx={{ color: 'text.secondary' }} />
                  </Box>
                  <Box sx={{ flex: 1, minWidth: 0 }}>
                    <Typography variant="body2" sx={{ fontWeight: 500 }}>
                      {filter.label}
                    </Typography>
                  </Box>
                  <IconButton
                    size="small"
                    onClick={(e) => {
                      e.stopPropagation();
                      // TODO: Handle filter menu
                    }}
                    sx={{ padding: 0.5 }}
                  >
                    <MoreVert fontSize="small" sx={{ color: 'text.secondary' }} />
                  </IconButton>
                </ListItem>
              );
            })}
          </List>
        </Box>
      </Paper>
    </Popover>
  );
};

export default FilterPopover;
