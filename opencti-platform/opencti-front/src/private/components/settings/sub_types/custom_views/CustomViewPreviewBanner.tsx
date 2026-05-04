import { CloseOutlined } from '@mui/icons-material';
import { Box, IconButton, Typography } from '@mui/material';
import ItemIcon from '../../../../../components/ItemIcon';
import { useTheme } from '@mui/styles';
import type { Theme } from '../../../../../components/Theme';

const CustomViewPreviewBanner = () => {
  const theme = useTheme<Theme>();
  const previewColor = theme.palette.designSystem.tertiary.orange['400'];
  return (
    <Box sx={{
      display: 'flex',
      alignItems: 'center',
      gap: 1,
      px: 2,
      py: 0.75,
      borderTop: `2px solid ${previewColor}`,
      background: theme.palette.background.drawer,
      color: previewColor,
      position: 'sticky',
      bottom: 0,
      left: 0,
      zIndex: 1000,
      width: '100%',
    }}
    >
      <Typography variant="body2" sx={{ fontWeight: 600 }}>
        Preview mode
      </Typography>
      <Typography variant="body2" sx={{ opacity: 0.8 }}>
        data shown as if viewed from :
      </Typography>
      {/* Entity chip — name + type icon */}
      <ItemIcon type="Intrusion-Set" size="small" />
      <Typography variant="body2" sx={{ fontWeight: 600 }}>
        My item  {/* the label from your Autocomplete option */}
      </Typography>
      {/* Easy exit */}
      <IconButton size="small" sx={{ ml: 'auto', color: previewColor }}>
        <CloseOutlined fontSize="small" />
      </IconButton>
    </Box>

  );
};

export default CustomViewPreviewBanner;
