import React from 'react';
import { Box, Typography, Avatar, Paper, IconButton } from '@mui/material';
import { ThumbUp, Favorite, SentimentSatisfied, MoreVert } from '@mui/icons-material';
import { useTheme } from '@mui/styles';
import type { Theme } from '../../../../../components/Theme';

export interface ChatMessage {
  id: string;
  sender: string;
  avatar: string;
  message: string;
  time: string;
  isOnline?: boolean;
  isOwn?: boolean; // آیا پیام از کاربر فعلی است
  reactions?: { type: string; count: number }[];
  attachment?: string;
}

interface ChatMessageItemProps {
  message: ChatMessage;
}

const ChatMessageItem: React.FC<ChatMessageItemProps> = ({ message }) => {
  const theme = useTheme<Theme>();
  const isDark = theme.palette.mode === 'dark';
  const isOwn = message.isOwn || false;

  return (
    <Box
      sx={{
        display: 'flex',
        gap: 1,
        marginBottom: 2,
        flexDirection: 'row',
        justifyContent: isOwn ? 'flex-end' : 'flex-start',
      }}
    >
      {!isOwn && (
        <Box sx={{ position: 'relative' }}>
          <Avatar
            sx={{
              width: 36,
              height: 36,
              backgroundColor: theme.palette.primary?.main || '#1976d2',
              fontSize: '0.75rem',
            }}
          >
            {message.avatar}
          </Avatar>
          {message.isOnline && (
            <Box
              sx={{
                position: 'absolute',
                top: 26,
                right: -4,
                width: 14,
                height: 14,
                borderRadius: '50%',
                backgroundColor: '#4caf50',
                border: `2px solid ${theme.palette.background?.paper || '#ffffff'}`,
              }}
            />
          )}
        </Box>
      )}
      <Box sx={{ flex: 1, maxWidth: '70%', display: 'flex', flexDirection: 'column', alignItems: isOwn ? 'flex-end' : 'flex-start' }}>
        <Box
          sx={{
            display: 'flex',
            alignItems: 'center',
            gap: 1,
            marginBottom: 0.5,
            flexDirection: 'row',
            justifyContent: isOwn ? 'flex-end' : 'flex-start',
          }}
        >
          <Typography variant="body2" sx={{ fontWeight: 600, fontSize: '0.875rem', color: theme.palette.text?.primary }}>
            {message.sender}
          </Typography>
          <Typography variant="caption" sx={{ fontSize: '0.75rem', color: theme.palette.text?.secondary }}>
            {message.time}
          </Typography>
        </Box>
        {message.attachment ? (
          <Paper
            sx={{
              padding: 1.5,
              backgroundColor: isOwn 
                ? (isDark ? 'rgba(25, 118, 210, 0.2)' : '#e3f2fd')
                : (isDark ? 'rgba(255, 255, 255, 0.05)' : '#f5f5f5'),
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              marginBottom: 1,
              borderRadius: 2,
            }}
          >
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
              <Typography variant="body2" sx={{ fontSize: '0.875rem', color: theme.palette.text?.primary }}>
                {message.message}
              </Typography>
            </Box>
            <IconButton size="small" sx={{ color: theme.palette.text?.primary }}>
              <MoreVert fontSize="small" />
            </IconButton>
          </Paper>
        ) : (
          <Paper
            sx={{
              padding: 1.5,
              backgroundColor: isOwn
                ? (isDark ? 'rgba(25, 118, 210, 0.2)' : '#e3f2fd')
                : (theme.palette.background?.paper || theme.palette.background?.default),
              borderRadius: 2,
              marginBottom: message.reactions ? 1 : 0,
            }}
          >
            <Typography variant="body2" sx={{ fontSize: '0.875rem', color: theme.palette.text?.primary }}>
              {message.message}
            </Typography>
          </Paper>
        )}
        {message.reactions && (
          <Box
            sx={{
              display: 'flex',
              gap: 1,
              marginTop: 0.5,
              flexDirection: 'row',
              justifyContent: isOwn ? 'flex-end' : 'flex-start',
            }}
          >
            {message.reactions.map((reaction, index) => (
              <Box
                key={index}
                sx={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: 0.5,
                  padding: '2px 8px',
                  backgroundColor: isDark ? 'rgba(255, 255, 255, 0.1)' : '#f5f5f5',
                  borderRadius: 1,
                  fontSize: '0.75rem',
                }}
              >
                {reaction.type === 'thumb' && <ThumbUp sx={{ fontSize: '0.875rem', color: theme.palette.text?.primary }} />}
                {reaction.type === 'heart' && <Favorite sx={{ fontSize: '0.875rem', color: '#f44336' }} />}
                {reaction.type === 'smile' && <SentimentSatisfied sx={{ fontSize: '0.875rem', color: theme.palette.text?.primary }} />}
                <Typography variant="caption" sx={{ fontSize: '0.75rem', color: theme.palette.text?.primary }}>
                  {reaction.count}
                </Typography>
              </Box>
            ))}
          </Box>
        )}
      </Box>
      {isOwn && (
        <Box sx={{ position: 'relative' }}>
          <Avatar
            sx={{
              width: 36,
              height: 36,
              backgroundColor: theme.palette.secondary?.main || '#9c27b0',
              fontSize: '0.75rem',
              color: '#ffffff',
            }}
          >
            {message.avatar}
          </Avatar>
        </Box>
      )}
    </Box>
  );
};

export default ChatMessageItem;

