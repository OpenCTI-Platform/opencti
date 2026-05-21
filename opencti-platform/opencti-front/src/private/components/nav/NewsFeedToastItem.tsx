import React, { FunctionComponent } from 'react';
import { Box, IconButton, Tooltip, Typography } from '@mui/material';
import { InsertChartOutlined, NotificationsOutlined, OpenInNewOutlined } from '@mui/icons-material';
import { useTheme } from '@mui/styles';
import type { Theme } from '../../../components/Theme';
import { useFormatter } from '../../../components/i18n';
import { useXTMHubResourceLink } from '../../../utils/hooks/useXTMHubResourceLink';

export interface NewsFeedToastData {
  id: string;
  title: string;
  news_feed_type: string;
  metadata: { key: string; readonly value: string | null | undefined }[];
}

const NEWS_FEED_ICON_MAP: Record<string, React.ElementType> = {
  RESOURCE_CUSTOM_DASHBOARD: InsertChartOutlined,
};

export const NEWS_FEED_TOAST_WIDTH = 450;

interface NewsFeedToastItemProps {
  item: NewsFeedToastData;
}

const NewsFeedToastItem: FunctionComponent<NewsFeedToastItemProps> = ({
  item,
}) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();

  const IconComponent: React.ElementType = NEWS_FEED_ICON_MAP[item.news_feed_type] ?? NotificationsOutlined;

  const urlPath = item.metadata?.find((m) => m?.key === 'url_path')?.value;
  const resourceLink = useXTMHubResourceLink(urlPath);

  const glassStyle = {
    backgroundColor: `${theme.palette.primary.main}22`,
    backdropFilter: 'blur(8px)',
    border: `1px solid ${theme.palette.primary.main}44`,
    borderRadius: '8px',
    boxShadow: theme.shadows[4],
  };

  return (
    <Box
      sx={{
        ...glassStyle,
        padding: theme.spacing(1),
        display: 'flex',
        alignItems: 'center',
        gap: theme.spacing(1.5),
        width: NEWS_FEED_TOAST_WIDTH,
      }}
    >
      {/* Type icon square */}
      <Box
        sx={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          flexShrink: 0,
          width: 48,
          height: 48,
          borderRadius: '6px',
          backgroundColor: `${theme.palette.primary.main}33`,
          border: `1px solid ${theme.palette.primary.main}55`,
        }}
      >
        <IconComponent sx={{ color: theme.palette.primary.main, fontSize: 26 }} />
      </Box>

      {/* Text content */}
      <Box sx={{ flex: 1, minWidth: 0 }}>
        {item.news_feed_type === 'RESOURCE_CUSTOM_DASHBOARD' && (
          <Typography variant="caption" sx={{ color: theme.palette.primary.main, display: 'block' }}>
            {t_i18n('New Custom Dashboard')}
          </Typography>
        )}
        <Typography variant="body2" sx={{ wordBreak: 'break-word', fontWeight: 700 }}>
          {item.title}
        </Typography>
      </Box>

      {/* Open in XTM Hub */}
      {resourceLink && (
        <Tooltip title={t_i18n('Open in XTM Hub')}>
          <IconButton
            component="a"
            href={resourceLink}
            target="_blank"
            rel="noopener noreferrer"
            size="small"
            color="primary"
            aria-label={t_i18n('Open in XTM Hub')}
            sx={{ flexShrink: 0 }}
          >
            <OpenInNewOutlined fontSize="small" />
          </IconButton>
        </Tooltip>
      )}
    </Box>
  );
};

export default NewsFeedToastItem;
