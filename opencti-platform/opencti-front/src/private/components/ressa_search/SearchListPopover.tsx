import React, { useState } from 'react';
import {
  Box,
  Typography,
  Paper,
  Popover,
  List,
  ListItem,
  ListItemSecondaryAction,
  Divider,
  Button,
  IconButton,
} from '@mui/material';
import {
  Search,
  Save,
  Edit,
} from '@mui/icons-material';
import { useFormatter } from '../../../components/i18n';

interface SearchItem {
  id: string;
  query: string;
  timestamp: string;
}

interface SearchListPopoverProps {
  open: boolean;
  anchorEl: HTMLElement | null;
  onClose: () => void;
  width: number;
  title: string;
  items: SearchItem[];
  icon: React.ReactNode;
  onSelectItem: (query: string) => void;
  onEditItem: (query: string, event: React.MouseEvent) => void;
  onSave: () => void;
  saveButtonText: string;
}

const SearchListPopover = ({
  open,
  anchorEl,
  onClose,
  width,
  title,
  items,
  icon,
  onSelectItem,
  onEditItem,
  onSave,
  saveButtonText,
}: SearchListPopoverProps) => {
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
            {items.map((item) => {
              const isHovered = hoveredItemId === item.id;
              return (
                <ListItem
                  key={item.id}
                  component="button"
                  onClick={() => onSelectItem(item.query)}
                  onMouseEnter={() => setHoveredItemId(item.id)}
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
                    {icon}
                  </Box>
                  <Box sx={{ flex: 1, minWidth: 0 }}>
                    <Typography variant="body2" sx={{ fontWeight: 500 }}>
                      {item.query}
                    </Typography>
                  </Box>
                  <ListItemSecondaryAction>
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
                      <Typography variant="caption" color="text.secondary" sx={{ marginRight: 1 }}>
                        {item.timestamp}
                      </Typography>
                      {isHovered && (
                        <Box
                          sx={{
                            display: 'flex',
                            gap: 0.5,
                            alignItems: 'center',
                          }}
                        >
                          <IconButton
                            size="small"
                            onClick={(e) => {
                              e.stopPropagation();
                              onSelectItem(item.query);
                            }}
                            sx={{ padding: 0.5 }}
                          >
                            <Search fontSize="small" sx={{ color: 'text.secondary' }} />
                          </IconButton>
                          <IconButton
                            size="small"
                            onClick={(e) => onEditItem(item.query, e)}
                            sx={{ padding: 0.5 }}
                          >
                            <Edit fontSize="small" sx={{ color: 'text.secondary' }} />
                          </IconButton>
                        </Box>
                      )}
                    </Box>
                  </ListItemSecondaryAction>
                </ListItem>
              );
            })}
          </List>
          <Divider sx={{ marginY: 2 }} />
          <Button
            startIcon={<Save />}
            variant="outlined"
            fullWidth
            onClick={onSave}
            sx={{
              textTransform: 'none',
              marginBottom: 1,
            }}
          >
            {saveButtonText}
          </Button>
          <Typography
            variant="caption"
            color="text.secondary"
            sx={{
              display: 'block',
              textAlign: 'center',
              fontSize: '0.75rem',
            }}
          >
            {t_i18n('Use arrow keys to navigate and Enter to select')}
          </Typography>
        </Box>
      </Paper>
    </Popover>
  );
};

export default SearchListPopover;
