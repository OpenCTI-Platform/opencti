import React from 'react';
import {
  Box,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableRow,
  Typography,
  Chip,
  Button,
} from '@mui/material';
import {
  BugReport as BugIcon,
} from '@mui/icons-material';
import { useTheme } from '@mui/styles';
import type { Theme } from '../../../../../components/Theme';
import { useFormatter } from '../../../../../components/i18n';
import type { Post } from './usePostsData';

interface PostsTableRendererProps {
  tab: number;
  data: Post[];
  theme: Theme;
}

const PostsTableRenderer: React.FC<PostsTableRendererProps> = ({ tab, data, theme }) => {
  const { t_i18n, fd } = useFormatter();

  // Category names mapping for Exploit Posts
  const categoryNames: { [key: number]: string } = {
    1: 'hacker',
    2: 'bug',
    3: 'malware',
    4: 'laws',
    5: 'carding',
  };

  const formatDate = (date: string | Date | undefined) => {
    if (!date) return '-';
    try {
      return fd(new Date(date));
    } catch {
      return '-';
    }
  };

  // Render table headers based on tab
  const renderHeaders = () => {
    switch (tab) {
      case 0: // Telegram Recents
        return (
          <>
            <TableCell sx={{ fontWeight: 600, fontSize: '0.875rem', color: theme.palette.text?.primary, borderBottom: 1, borderColor: 'divider' }}>
              Message ID
            </TableCell>
            <TableCell sx={{ fontWeight: 600, fontSize: '0.875rem', color: theme.palette.text?.primary, borderBottom: 1, borderColor: 'divider' }}>
              Channel
            </TableCell>
            <TableCell sx={{ fontWeight: 600, fontSize: '0.875rem', color: theme.palette.text?.primary, borderBottom: 1, borderColor: 'divider', width: 150 }}>
              Created At
            </TableCell>
            <TableCell sx={{ fontWeight: 600, fontSize: '0.875rem', color: theme.palette.text?.primary, borderBottom: 1, borderColor: 'divider', width: 100 }}></TableCell>
          </>
        );

      case 1: // Exploit Posts
        return (
          <>
            <TableCell sx={{ fontWeight: 600, fontSize: '0.875rem', color: theme.palette.text?.primary, borderBottom: 1, borderColor: 'divider' }}>
              Title
            </TableCell>
            <TableCell sx={{ fontWeight: 600, fontSize: '0.875rem', color: theme.palette.text?.primary, borderBottom: 1, borderColor: 'divider', width: 120 }}>
              Category
            </TableCell>
            <TableCell sx={{ fontWeight: 600, fontSize: '0.875rem', color: theme.palette.text?.primary, borderBottom: 1, borderColor: 'divider', width: 150 }}>
              Created At
            </TableCell>
            <TableCell sx={{ fontWeight: 600, fontSize: '0.875rem', color: theme.palette.text?.primary, borderBottom: 1, borderColor: 'divider', width: 100 }}></TableCell>
          </>
        );

      case 2: // Russian Market Items
        return (
          <>
            <TableCell sx={{ fontWeight: 600, fontSize: '0.875rem', color: theme.palette.text?.primary, borderBottom: 1, borderColor: 'divider', width: 80 }}>
              ID
            </TableCell>
            <TableCell sx={{ fontWeight: 600, fontSize: '0.875rem', color: theme.palette.text?.primary, borderBottom: 1, borderColor: 'divider', width: 100 }}>
              Country
            </TableCell>
            <TableCell sx={{ fontWeight: 600, fontSize: '0.875rem', color: theme.palette.text?.primary, borderBottom: 1, borderColor: 'divider', width: 100 }}>
              City
            </TableCell>
            <TableCell sx={{ fontWeight: 600, fontSize: '0.875rem', color: theme.palette.text?.primary, borderBottom: 1, borderColor: 'divider', width: 100 }}>
              Vendor
            </TableCell>
            <TableCell sx={{ fontWeight: 600, fontSize: '0.875rem', color: theme.palette.text?.primary, borderBottom: 1, borderColor: 'divider', width: 100 }}>
              Price
            </TableCell>
            <TableCell sx={{ fontWeight: 600, fontSize: '0.875rem', color: theme.palette.text?.primary, borderBottom: 1, borderColor: 'divider', width: 150 }}>
              Date
            </TableCell>
            <TableCell sx={{ fontWeight: 600, fontSize: '0.875rem', color: theme.palette.text?.primary, borderBottom: 1, borderColor: 'divider', width: 100 }}></TableCell>
          </>
        );

      case 3: // IntelX Leaks
        return (
          <>
            <TableCell sx={{ fontWeight: 600, fontSize: '0.875rem', color: theme.palette.text?.primary, borderBottom: 1, borderColor: 'divider' }}>
              Domain
            </TableCell>
            <TableCell sx={{ fontWeight: 600, fontSize: '0.875rem', color: theme.palette.text?.primary, borderBottom: 1, borderColor: 'divider', width: 120 }}>
              User
            </TableCell>
            <TableCell sx={{ fontWeight: 600, fontSize: '0.875rem', color: theme.palette.text?.primary, borderBottom: 1, borderColor: 'divider', width: 120 }}>
              Password Type
            </TableCell>
            <TableCell sx={{ fontWeight: 600, fontSize: '0.875rem', color: theme.palette.text?.primary, borderBottom: 1, borderColor: 'divider', width: 150 }}>
              Date
            </TableCell>
            <TableCell sx={{ fontWeight: 600, fontSize: '0.875rem', color: theme.palette.text?.primary, borderBottom: 1, borderColor: 'divider', width: 100 }}></TableCell>
          </>
        );

      case 4: // IntelX Items
        return (
          <>
            <TableCell sx={{ fontWeight: 600, fontSize: '0.875rem', color: theme.palette.text?.primary, borderBottom: 1, borderColor: 'divider' }}>
              Domain
            </TableCell>
            <TableCell sx={{ fontWeight: 600, fontSize: '0.875rem', color: theme.palette.text?.primary, borderBottom: 1, borderColor: 'divider' }}>
              Name
            </TableCell>
            <TableCell sx={{ fontWeight: 600, fontSize: '0.875rem', color: theme.palette.text?.primary, borderBottom: 1, borderColor: 'divider', width: 120 }}>
              Type
            </TableCell>
            <TableCell sx={{ fontWeight: 600, fontSize: '0.875rem', color: theme.palette.text?.primary, borderBottom: 1, borderColor: 'divider', width: 120 }}>
              Bucket
            </TableCell>
            <TableCell sx={{ fontWeight: 600, fontSize: '0.875rem', color: theme.palette.text?.primary, borderBottom: 1, borderColor: 'divider', width: 150 }}>
              Date
            </TableCell>
            <TableCell sx={{ fontWeight: 600, fontSize: '0.875rem', color: theme.palette.text?.primary, borderBottom: 1, borderColor: 'divider', width: 100 }}></TableCell>
          </>
        );

      default:
        return null;
    }
  };

  // Render table rows based on tab
  const renderRow = (post: Post) => {
    switch (tab) {
      case 0: // Telegram Recents
        return (
          <>
            <TableCell sx={{ fontSize: '0.875rem', color: theme.palette.text?.primary, borderBottom: 1, borderColor: 'divider' }}>
              {post.messageId || '-'}
            </TableCell>
            <TableCell sx={{ fontSize: '0.875rem', color: theme.palette.text?.primary, borderBottom: 1, borderColor: 'divider' }}>
              {(post as any).channel?.title || (post as any).channel?.username || '-'}
            </TableCell>
            <TableCell sx={{ fontSize: '0.875rem', color: theme.palette.text?.secondary, borderBottom: 1, borderColor: 'divider' }}>
              {formatDate((post as any).date)}
            </TableCell>
            <TableCell sx={{ borderBottom: 1, borderColor: 'divider' }}>
              <Button
                size="small"
                variant="text"
                sx={{ textTransform: 'none', fontSize: '0.875rem', color: theme.palette.primary.main }}
              >
                View
              </Button>
            </TableCell>
          </>
        );

      case 1: // Exploit Posts
        const categoryId = (post as any).categoryId;
        const categoryName = categoryId ? categoryNames[categoryId] || categoryId : '-';
        return (
          <>
            <TableCell sx={{ fontSize: '0.875rem', color: theme.palette.text?.primary, borderBottom: 1, borderColor: 'divider', maxWidth: 600 }}>
              <Typography
                variant="body2"
                sx={{
                  overflow: 'hidden',
                  textOverflow: 'ellipsis',
                  display: '-webkit-box',
                  WebkitLineClamp: 2,
                  WebkitBoxOrient: 'vertical',
                }}
              >
                {(post as any).title || '-'}
              </Typography>
            </TableCell>
            <TableCell sx={{ borderBottom: 1, borderColor: 'divider' }}>
              <Chip
                icon={<BugIcon sx={{ fontSize: '0.875rem !important' }} />}
                label={categoryName}
                size="small"
                variant="outlined"
                sx={{
                  fontSize: '0.75rem',
                  height: 24,
                  borderColor: theme.palette.divider,
                  color: theme.palette.text?.primary,
                  paddingX: 1,
                }}
              />
            </TableCell>
            <TableCell sx={{ fontSize: '0.875rem', color: theme.palette.text?.secondary, borderBottom: 1, borderColor: 'divider' }}>
              {formatDate((post as any).createdDate || (post as any).createdAt)}
            </TableCell>
            <TableCell sx={{ borderBottom: 1, borderColor: 'divider' }}>
              <Button
                size="small"
                variant="text"
                sx={{ textTransform: 'none', fontSize: '0.875rem', color: theme.palette.primary.main }}
              >
                View
              </Button>
            </TableCell>
          </>
        );

      case 2: // Russian Market Items
        return (
          <>
            <TableCell sx={{ fontSize: '0.875rem', color: theme.palette.text?.primary, borderBottom: 1, borderColor: 'divider' }}>
              {(post as any).id || '-'}
            </TableCell>
            <TableCell sx={{ fontSize: '0.875rem', color: theme.palette.text?.primary, borderBottom: 1, borderColor: 'divider' }}>
              {(post as any).country || '-'}
            </TableCell>
            <TableCell sx={{ fontSize: '0.875rem', color: theme.palette.text?.primary, borderBottom: 1, borderColor: 'divider' }}>
              {(post as any).city || '-'}
            </TableCell>
            <TableCell sx={{ fontSize: '0.875rem', color: theme.palette.text?.primary, borderBottom: 1, borderColor: 'divider' }}>
              {(post as any).vendor || '-'}
            </TableCell>
            <TableCell sx={{ fontSize: '0.875rem', color: theme.palette.text?.primary, borderBottom: 1, borderColor: 'divider' }}>
              {(post as any).price ? `${(post as any).price}` : '-'}
            </TableCell>
            <TableCell sx={{ fontSize: '0.875rem', color: theme.palette.text?.secondary, borderBottom: 1, borderColor: 'divider' }}>
              {formatDate((post as any).date || (post as any).created_at)}
            </TableCell>
            <TableCell sx={{ borderBottom: 1, borderColor: 'divider' }}>
              <Button
                size="small"
                variant="text"
                sx={{ textTransform: 'none', fontSize: '0.875rem', color: theme.palette.primary.main }}
              >
                View
              </Button>
            </TableCell>
          </>
        );

      case 3: // IntelX Leaks
        return (
          <>
            <TableCell sx={{ fontSize: '0.875rem', color: theme.palette.text?.primary, borderBottom: 1, borderColor: 'divider', maxWidth: 300 }}>
              <Typography
                variant="body2"
                sx={{
                  overflow: 'hidden',
                  textOverflow: 'ellipsis',
                  display: '-webkit-box',
                  WebkitLineClamp: 1,
                  WebkitBoxOrient: 'vertical',
                }}
              >
                {(post as any).domain || '-'}
              </Typography>
            </TableCell>
            <TableCell sx={{ fontSize: '0.875rem', color: theme.palette.text?.primary, borderBottom: 1, borderColor: 'divider' }}>
              {(post as any).user || '-'}
            </TableCell>
            <TableCell sx={{ fontSize: '0.875rem', color: theme.palette.text?.primary, borderBottom: 1, borderColor: 'divider' }}>
              {(post as any).passwordtype || '-'}
            </TableCell>
            <TableCell sx={{ fontSize: '0.875rem', color: theme.palette.text?.secondary, borderBottom: 1, borderColor: 'divider' }}>
              {formatDate((post as any).date || (post as any).added)}
            </TableCell>
            <TableCell sx={{ borderBottom: 1, borderColor: 'divider' }}>
              <Button
                size="small"
                variant="text"
                sx={{ textTransform: 'none', fontSize: '0.875rem', color: theme.palette.primary.main }}
              >
                View
              </Button>
            </TableCell>
          </>
        );

      case 4: // IntelX Items
        return (
          <>
            <TableCell sx={{ fontSize: '0.875rem', color: theme.palette.text?.primary, borderBottom: 1, borderColor: 'divider', maxWidth: 300 }}>
              <Typography
                variant="body2"
                sx={{
                  overflow: 'hidden',
                  textOverflow: 'ellipsis',
                  display: '-webkit-box',
                  WebkitLineClamp: 1,
                  WebkitBoxOrient: 'vertical',
                }}
              >
                {(post as any).domain || '-'}
              </Typography>
            </TableCell>
            <TableCell sx={{ fontSize: '0.875rem', color: theme.palette.text?.primary, borderBottom: 1, borderColor: 'divider', maxWidth: 300 }}>
              <Typography
                variant="body2"
                sx={{
                  overflow: 'hidden',
                  textOverflow: 'ellipsis',
                  display: '-webkit-box',
                  WebkitLineClamp: 1,
                  WebkitBoxOrient: 'vertical',
                }}
              >
                {(post as any).item?.name || '-'}
              </Typography>
            </TableCell>
            <TableCell sx={{ fontSize: '0.875rem', color: theme.palette.text?.primary, borderBottom: 1, borderColor: 'divider' }}>
              {(post as any).item?.type || '-'}
            </TableCell>
            <TableCell sx={{ fontSize: '0.875rem', color: theme.palette.text?.primary, borderBottom: 1, borderColor: 'divider' }}>
              {(post as any).item?.bucket || '-'}
            </TableCell>
            <TableCell sx={{ fontSize: '0.875rem', color: theme.palette.text?.secondary, borderBottom: 1, borderColor: 'divider' }}>
              {formatDate((post as any).item?.date || (post as any).item?.added)}
            </TableCell>
            <TableCell sx={{ borderBottom: 1, borderColor: 'divider' }}>
              <Button
                size="small"
                variant="text"
                sx={{ textTransform: 'none', fontSize: '0.875rem', color: theme.palette.primary.main }}
              >
                View
              </Button>
            </TableCell>
          </>
        );

      default:
        return null;
    }
  };

  return (
    <Table>
      <TableHead>
        <TableRow>
          {renderHeaders()}
        </TableRow>
      </TableHead>
      <TableBody>
        {data.map((post) => (
          <TableRow
            key={post.id}
            sx={{
              '&:hover': {
                backgroundColor: theme.palette.action?.hover,
              },
            }}
          >
            {renderRow(post)}
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
};

export default PostsTableRenderer;
