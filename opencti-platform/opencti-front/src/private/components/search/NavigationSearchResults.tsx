import React from 'react';
import { Link } from 'react-router';
import { Box, List, ListItemButton, ListItemIcon, ListItemText, Typography } from '@mui/material';
import { ChevronRightOutlined, DescriptionOutlined } from '@mui/icons-material';
import { useFormatter } from '../../../components/i18n';
import useNavSearch from '../nav/useNavSearch';

// "Application pages" card of the search results: deep links to platform pages matching the keyword.
const NavigationSearchResults = ({ keyword }: { keyword?: string | null }) => {
  const { t_i18n } = useFormatter();
  const results = useNavSearch(keyword);
  if (results.length === 0) return null;

  return (
    <Box
      sx={{
        mb: 2,
        p: 2,
        border: 1,
        borderColor: 'divider',
        borderRadius: 1,
        bgcolor: 'background.paper',
      }}
    >
      <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
        {t_i18n('Application pages')}
      </Typography>
      <List disablePadding>
        {results.map(({ path, label, parents }) => (
          <ListItemButton key={path} component={Link} to={path} sx={{ borderRadius: 1 }}>
            <ListItemIcon sx={{ minWidth: 48 }}>
              <DescriptionOutlined fontSize="small" />
            </ListItemIcon>
            <ListItemText
              primary={label}
              secondary={parents.join(' > ') || undefined}
            />
            <ChevronRightOutlined fontSize="small" color="disabled" />
          </ListItemButton>
        ))}
      </List>
    </Box>
  );
};

export default NavigationSearchResults;
