import React, { useState, useEffect, useCallback } from 'react';
import {
  Box,
  Card,
  Typography,
  List,
  Divider,
  Button,
  IconButton,
  TextField,
  CircularProgress,
} from '@mui/material';
import {
  SendOutlined,
  Menu,
  Edit,
  GridView,
  ArrowDropDown,
  VideoCall,
  Add,
} from '@mui/icons-material';
import { useTheme } from '@mui/styles';
import type { Theme } from '../../../../../components/Theme';
import { useFormatter } from '../../../../../components/i18n';
import ChatListItem, { ChatItem } from './ChatListItem';
import ChatMessageItem, { ChatMessage } from './ChatMessageItem';

const ChatInterface: React.FC = () => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const isDark = theme.palette.mode === 'dark';
  
  const [channels, setChannels] = useState<ChatItem[]>([]);
  const [selectedChannel, setSelectedChannel] = useState<string | null>(null);
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [loadingChannels, setLoadingChannels] = useState<boolean>(true);
  const [loadingMessages, setLoadingMessages] = useState<boolean>(false);
  const [selectedChannelInfo, setSelectedChannelInfo] = useState<any>(null);

  // Format date to relative time
  const formatTime = useCallback((date: string | Date) => {
    const dateObj = typeof date === 'string' ? new Date(date) : date;
    const now = new Date();
    const diff = now.getTime() - dateObj.getTime();
    const minutes = Math.floor(diff / 60000);
    const hours = Math.floor(diff / 3600000);
    const days = Math.floor(diff / 86400000);

    if (minutes < 1) return t_i18n('Just now');
    if (minutes < 60) return `${minutes} ${t_i18n('min ago')}`;
    if (hours < 24) return `${hours} ${t_i18n('h ago')}`;
    if (days < 7) return `${days} ${t_i18n('d ago')}`;
    return dateObj.toLocaleDateString();
  }, [t_i18n]);

  // Fetch Telegram channels
  useEffect(() => {
    const fetchChannels = async () => {
      try {
        setLoadingChannels(true);
        const apiUrl = (window as any).RESSA_DWM_API_URL 
          || (window as any).PUBLIC_VITE_API_URL 
          || 'http://172.16.40.15:3400';
        const endpoint = `${apiUrl}/graphql`;

        const query = `
          query GetTelegramChannels {
            getTelegramChannels {
              id
              title
              username
              avatarUrl
              lastMessage {
                date
              }
            }
          }
        `;

        const response = await fetch(endpoint, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({ query }),
        });

        if (response.ok) {
          const result = await response.json();
          if (result.data?.getTelegramChannels) {
            const channelsData = result.data.getTelegramChannels.map((channel: any) => ({
              id: channel.id.toString(),
              name: channel.title || channel.username || 'Unknown',
              avatar: channel.title?.charAt(0).toUpperCase() || '?',
              lastMessage: channel.lastMessage?.content || '',
              time: channel.lastMessage?.date ? formatTime(channel.lastMessage.date) : '',
              isOnline: false,
              isGroup: false,
              channelData: channel, // Store full channel data
            }));

            // Sort by last message date (most recent first)
            channelsData.sort((a: ChatItem, b: ChatItem) => {
              const aDate = channelsData.find((c: any) => c.id === a.id)?.channelData?.lastMessage?.date;
              const bDate = channelsData.find((c: any) => c.id === b.id)?.channelData?.lastMessage?.date;
              if (!aDate && !bDate) return 0;
              if (!aDate) return 1;
              if (!bDate) return -1;
              return new Date(bDate).getTime() - new Date(aDate).getTime();
            });

            setChannels(channelsData);
            
            // Select first channel by default
            if (channelsData.length > 0 && !selectedChannel) {
              setSelectedChannel(channelsData[0].id);
              setSelectedChannelInfo(channelsData[0].channelData);
            }
          }
        }
      } catch (err) {
        console.error('Failed to fetch Telegram channels:', err);
      } finally {
        setLoadingChannels(false);
      }
    };

    fetchChannels();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Fetch messages for selected channel
  useEffect(() => {
    if (!selectedChannel) return;

    const fetchMessages = async () => {
      try {
        setLoadingMessages(true);
        const apiUrl = (window as any).RESSA_DWM_API_URL 
          || (window as any).PUBLIC_VITE_API_URL 
          || 'http://172.16.40.15:3400';
        const endpoint = `${apiUrl}/graphql`;

        const query = `
          query GetTelegramMessages($filters: [String], $page: Int, $perPage: Int) {
            getTelegramMessages(page: $page, perPage: $perPage, filters: $filters) {
              total
              data {
                id
                messageId
                message
                date
                channel {
                  id
                  title
                  username
                }
              }
            }
          }
        `;

        const response = await fetch(endpoint, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            query,
            variables: {
              page: 1,
              perPage: 50,
              filters: [`channelId:${selectedChannel}:=`],
            },
          }),
        });

        if (response.ok) {
          const result = await response.json();
          if (result.data?.getTelegramMessages?.data) {
            const messagesData = result.data.getTelegramMessages.data.map((msg: any, index: number) => ({
              id: msg.id?.toString() || index.toString(),
              sender: msg.channel?.title || msg.channel?.username || 'Unknown',
              avatar: (msg.channel?.title || msg.channel?.username || '?').charAt(0).toUpperCase(),
              message: msg.message || '',
              time: msg.date ? formatTime(msg.date) : '',
              isOnline: false,
              isOwn: false,
            }));

            // Sort by date (newest first)
            messagesData.sort((a: ChatMessage, b: ChatMessage) => {
              // This is a simplified sort - in real app you'd parse dates properly
              return 0;
            });

            setMessages(messagesData);
          }
        }
      } catch (err) {
        console.error('Failed to fetch Telegram messages:', err);
      } finally {
        setLoadingMessages(false);
      }
    };

    fetchMessages();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedChannel]);

  // Split channels into pinned and recent (for now, all are recent)
  const pinnedChats: ChatItem[] = [];
  const recentChats: ChatItem[] = channels;

  return (
    <Card variant="outlined" sx={{ backgroundColor: theme.palette.background?.paper || theme.palette.background?.default, height: 600 }}>
      <Box sx={{ display: 'flex', height: '100%' }}>
        {/* Left Sidebar - Chat List */}
        <Box
          sx={{
            width: '25%',
            borderRight: `1px solid ${theme.palette.divider || (isDark ? 'rgba(255, 255, 255, 0.12)' : 'rgba(0, 0, 0, 0.12)')}`,
            display: 'flex',
            flexDirection: 'column',
            backgroundColor: theme.palette.background?.paper || theme.palette.background?.default,
          }}
        >
          {/* Header */}
          <Box
            sx={{
              padding: 2,
              borderBottom: `1px solid ${theme.palette.divider || (isDark ? 'rgba(255, 255, 255, 0.12)' : 'rgba(0, 0, 0, 0.12)')}`,
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              minHeight: '64px',
              height: '64px',
            }}
          >
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
              <Typography variant="h6" sx={{ fontWeight: 600, fontSize: '1rem', color: theme.palette.text?.primary }}>
                {t_i18n('Telegram')}
              </Typography>
              <ArrowDropDown sx={{ color: theme.palette.text?.primary }} />
            </Box>
            <Box sx={{ display: 'flex', gap: 0.5 }}>
              <IconButton size="small" sx={{ color: theme.palette.text?.primary }}>
                <Menu fontSize="small" />
              </IconButton>
              <IconButton size="small" sx={{ color: theme.palette.text?.primary }}>
                <Edit fontSize="small" />
              </IconButton>
              <IconButton size="small" sx={{ color: theme.palette.text?.primary }}>
                <GridView fontSize="small" />
              </IconButton>
            </Box>
          </Box>

          {/* Chat List */}
          <Box sx={{ flex: 1, overflowY: 'auto' }}>
            {/* Pinned Section */}
            {pinnedChats.length > 0 && (
              <Box>
                <Typography
                  variant="caption"
                  sx={{
                    padding: '8px 16px',
                    color: theme.palette.text?.secondary,
                    fontSize: '0.75rem',
                    fontWeight: 600,
                    textTransform: 'uppercase',
                  }}
                >
                  {t_i18n('Pinned')}
                </Typography>
                <List sx={{ padding: 0 }}>
                  {pinnedChats.map((chat) => (
                    <ChatListItem 
                      key={chat.id} 
                      chat={chat} 
                      isSelected={selectedChannel === chat.id}
                      onClick={() => {
                        setSelectedChannel(chat.id);
                        setSelectedChannelInfo((chat as any).channelData);
                      }}
                    />
                  ))}
                </List>
                <Divider />
              </Box>
            )}

            {/* Recent Section */}
            {recentChats.length > 0 && (
              <Box>
                <Typography
                  variant="caption"
                  sx={{
                    padding: '8px 16px',
                    color: theme.palette.text?.secondary,
                    fontSize: '0.75rem',
                    fontWeight: 600,
                    textTransform: 'uppercase',
                  }}
                >
                  {t_i18n('Recent')}
                </Typography>
                <List sx={{ padding: 0 }}>
                  {loadingChannels ? (
                    <Box sx={{ display: 'flex', justifyContent: 'center', padding: 2 }}>
                      <CircularProgress size={24} />
                    </Box>
                  ) : (
                    recentChats.map((chat) => (
                      <ChatListItem 
                        key={chat.id} 
                        chat={chat} 
                        isSelected={selectedChannel === chat.id}
                        onClick={() => {
                          setSelectedChannel(chat.id);
                          setSelectedChannelInfo((chat as any).channelData);
                        }}
                      />
                    ))
                  )}
                </List>
              </Box>
            )}
          </Box>
        </Box>

        {/* Right Side - Chat Content */}
        <Box sx={{ flex: 1, display: 'flex', flexDirection: 'column', backgroundColor: theme.palette.background?.default }}>
          {/* Chat Header */}
          <Box
            sx={{
              padding: 2,
              borderBottom: `1px solid ${theme.palette.divider || (isDark ? 'rgba(255, 255, 255, 0.12)' : 'rgba(0, 0, 0, 0.12)')}`,
              backgroundColor: theme.palette.background?.paper || theme.palette.background?.default,
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              minHeight: '64px',
              height: '64px',
            }}
          >
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
              <Box
                sx={{
                  backgroundColor: theme.palette.primary?.main || '#1976d2',
                  borderRadius: 1,
                  padding: '4px',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                }}
              >
                <GridView sx={{ fontSize: '1.25rem', color: '#ffffff' }} />
              </Box>
              <Typography variant="body2" sx={{ fontWeight: 600, fontSize: '0.875rem', color: theme.palette.text?.primary }}>
                {selectedChannelInfo?.title || selectedChannelInfo?.username || t_i18n('Channel Name')}
              </Typography>
            </Box>
            <Box sx={{ display: 'flex', gap: 1 }}>
              <Button
                variant="outlined"
                size="small"
                startIcon={<VideoCall />}
                sx={{
                  textTransform: 'none',
                  fontSize: '0.875rem',
                  color: theme.palette.text?.secondary,
                  borderColor: theme.palette.divider || (isDark ? 'rgba(255, 255, 255, 0.12)' : 'rgba(0, 0, 0, 0.12)'),
                  '&:hover': {
                    borderColor: theme.palette.divider || (isDark ? 'rgba(255, 255, 255, 0.2)' : 'rgba(0, 0, 0, 0.2)'),
                    backgroundColor: theme.palette.action?.hover,
                  },
                }}
              >
                {t_i18n('Meet now')}
              </Button>
              <Box sx={{ display: 'flex', borderRadius: 1, overflow: 'hidden' }}>
                <Button
                  variant="contained"
                  size="small"
                  startIcon={<Add />}
                  sx={{
                    textTransform: 'none',
                    fontSize: '0.875rem',
                    backgroundColor: theme.palette.primary?.main || '#1976d2',
                    color: '#ffffff',
                    borderRadius: 0,
                    borderStartStartRadius: 4,
                    borderEndStartRadius: 4,
                    '&:hover': {
                      backgroundColor: theme.palette.primary?.dark || '#1565c0',
                    },
                  }}
                >
                  {t_i18n('New meeting')}
                </Button>
                <Button
                  variant="contained"
                  size="small"
                  sx={{
                    minWidth: 'auto',
                    padding: '6px 8px',
                    backgroundColor: theme.palette.primary?.main || '#1976d2',
                    color: '#ffffff',
                    borderRadius: 0,
                    borderStartEndRadius: 4,
                    borderEndEndRadius: 4,
                    borderLeft: '1px solid rgba(255, 255, 255, 0.2)',
                    '&:hover': {
                      backgroundColor: theme.palette.primary?.dark || '#1565c0',
                    },
                  }}
                >
                  <ArrowDropDown />
                </Button>
              </Box>
            </Box>
          </Box>

          {/* Messages */}
          <Box sx={{ flex: 1, overflowY: 'auto', padding: 2 }}>
            {loadingMessages ? (
              <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', minHeight: '200px' }}>
                <CircularProgress />
              </Box>
            ) : messages.length > 0 ? (
              messages.map((msg) => (
                <ChatMessageItem key={msg.id} message={msg} />
              ))
            ) : (
              <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', minHeight: '200px' }}>
                <Typography variant="body2" sx={{ color: theme.palette.text?.secondary }}>
                  {t_i18n('No messages')}
                </Typography>
              </Box>
            )}
          </Box>

          {/* Input Area */}
          <Box
            sx={{
              padding: 2,
              borderTop: `1px solid ${theme.palette.divider || (isDark ? 'rgba(255, 255, 255, 0.12)' : 'rgba(0, 0, 0, 0.12)')}`,
              backgroundColor: theme.palette.background?.paper || theme.palette.background?.default,
            }}
          >
            <TextField
              fullWidth
              placeholder={t_i18n('Type a message...')}
              variant="outlined"
              size="small"
              InputProps={{
                endAdornment: (
                  <IconButton size="small" color="primary">
                    <SendOutlined />
                  </IconButton>
                ),
              }}
            />
          </Box>
        </Box>
      </Box>
    </Card>
  );
};

export default ChatInterface;

