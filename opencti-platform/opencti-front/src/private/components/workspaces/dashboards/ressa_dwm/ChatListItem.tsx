import React from 'react';
import { ListItem, ListItemAvatar, ListItemText, Typography, Box, Avatar } from '@mui/material';
import { useTheme } from '@mui/styles';
import type { Theme } from '../../../../../components/Theme';

export interface ChatItem {
  id: string;
  name: string;
  avatar: string;
  lastMessage: string;
  time: string;
  isOnline?: boolean;
  isGroup?: boolean;
}

interface ChatListItemProps {
  chat: ChatItem;
  isSelected?: boolean;
  onClick?: () => void;
}

const ChatListItem: React.FC<ChatListItemProps> = ({ chat, isSelected = false, onClick }) => {
  const theme = useTheme<Theme>();
  const isDark = theme.palette.mode === 'dark';
  
  return (
    <ListItem
      onClick={onClick}
      sx={{
        padding: '8px 16px',
        cursor: 'pointer',
        backgroundColor: isSelected ? theme.palette.action?.selected : 'transparent',
        '&:hover': { backgroundColor: theme.palette.action?.hover },
      }}
    >
      <ListItemAvatar>
        <Box sx={{ position: 'relative' }}>
          <Avatar
            sx={{
              width: 40,
              height: 40,
              backgroundColor: chat.isGroup ? (theme.palette.secondary?.main || '#9c27b0') : (theme.palette.primary?.main || '#1976d2'),
              fontSize: '0.875rem',
            }}
          >
            {chat.avatar}
          </Avatar>
          {chat.isOnline && (
            <Box
              sx={{
                position: 'absolute',
                bottom: -2,
                right: 12,
                width: 14,
                height: 14,
                borderRadius: '50%',
                backgroundColor: '#4caf50',
                border: `2px solid ${theme.palette.background?.paper || '#ffffff'}`,
                zIndex: 1,
              }}
            />
          )}
        </Box>
      </ListItemAvatar>
      <ListItemText
        primary={
          <Typography variant="body2" sx={{ fontWeight: 500, fontSize: '0.875rem', color: theme.palette.text?.primary }}>
            {chat.name}
          </Typography>
        }
        secondary={
          <Typography
            variant="caption"
            sx={{
              fontSize: '0.75rem',
              color: theme.palette.text?.secondary,
              overflow: 'hidden',
              textOverflow: 'ellipsis',
              whiteSpace: 'nowrap',
            }}
          >
            {chat.lastMessage}
          </Typography>
        }
      />
      <Typography variant="caption" sx={{ fontSize: '0.75rem', color: theme.palette.text?.secondary, marginInlineStart: 1 }}>
        {chat.time}
      </Typography>
    </ListItem>
  );
};

export default ChatListItem;

