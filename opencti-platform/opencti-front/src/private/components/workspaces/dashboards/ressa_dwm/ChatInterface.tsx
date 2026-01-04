import React, { useState, useEffect, useCallback, useRef } from 'react';
import {
  Box,
  Card,
  Typography,
  List,
  Divider,
  IconButton,
  CircularProgress,
} from '@mui/material';
import {
  GridView,
  ArrowDropDown,
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
  const [loadingMore, setLoadingMore] = useState<boolean>(false);
  const [selectedChannelInfo, setSelectedChannelInfo] = useState<any>(null);
  const [currentPage, setCurrentPage] = useState<number>(1);
  const [hasMore, setHasMore] = useState<boolean>(true);
  const [totalMessages, setTotalMessages] = useState<number>(0);
  const messagesContainerRef = useRef<HTMLDivElement>(null);
  const channelDataMapRef = useRef<Map<string, any>>(new Map());

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
        } else {
          // Use mock data if API fails
          throw new Error('API response not ok');
        }
      } catch (err) {
        console.error('Failed to fetch Telegram channels:', err);
        
        // Mock data for channels
        const mockChannelData1 = { id: 1, title: 'IRLeaks', username: 'irleaks' };
        const mockChannelData2 = { id: 2, title: 'bakhtak', username: 'bakhtak' };
        const mockChannelData3 = { id: 3, title: 'We Red Evils Original', username: 'weredevils' };
        
        channelDataMapRef.current.set('1', mockChannelData1);
        channelDataMapRef.current.set('2', mockChannelData2);
        channelDataMapRef.current.set('3', mockChannelData3);
        
        const mockChannels: ChatItem[] = [
          {
            id: '1',
            name: 'IRLeaks',
            avatar: 'I',
            lastMessage: 'New leak detected in banking system',
            time: formatTime(new Date(Date.now() - 5 * 60000)),
            isOnline: true,
            isGroup: false,
          },
          {
            id: '2',
            name: 'bakhtak',
            avatar: 'B',
            lastMessage: 'New information available',
            time: formatTime(new Date(Date.now() - 30 * 60000)),
            isOnline: false,
            isGroup: false,
          },
          {
            id: '3',
            name: 'We Red Evils Original',
            avatar: 'W',
            lastMessage: 'New update published',
            time: formatTime(new Date(Date.now() - 2 * 3600000)),
            isOnline: false,
            isGroup: false,
          },
        ];
        
        setChannels(mockChannels);
        if (mockChannels.length > 0 && !selectedChannel) {
          setSelectedChannel(mockChannels[0].id);
          setSelectedChannelInfo(mockChannelData1);
        }
      } finally {
        setLoadingChannels(false);
      }
    };

    fetchChannels();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Fetch messages function with pagination support
  const fetchMessages = useCallback(async (page: number, append: boolean = false) => {
    if (!selectedChannel) return;

    try {
      if (append) {
        setLoadingMore(true);
      } else {
        setLoadingMessages(true);
      }

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
            page,
            perPage: 50,
            filters: [`channelId:${selectedChannel}:=`],
          },
        }),
      });

      if (response.ok) {
        const result = await response.json();
        if (result.data?.getTelegramMessages) {
          const total = result.data.getTelegramMessages.total || 0;
          setTotalMessages(total);

          if (result.data.getTelegramMessages.data) {
            const messagesData = result.data.getTelegramMessages.data.map((msg: any, index: number) => ({
              id: msg.id?.toString() || `${page}-${index}`,
              sender: msg.channel?.title || msg.channel?.username || 'Unknown',
              avatar: (msg.channel?.title || msg.channel?.username || '?').charAt(0).toUpperCase(),
              message: msg.message || '',
              time: msg.date ? formatTime(msg.date) : '',
              isOnline: false,
              isOwn: false,
            }));

            if (append) {
              setMessages((prev) => {
                const newMessages = [...prev, ...messagesData];
                setHasMore(newMessages.length < total);
                return newMessages;
              });
            } else {
              setMessages(messagesData);
              setHasMore(messagesData.length < total);
            }
          }
        } else {
          // Use mock data if API response is invalid
          throw new Error('Invalid API response');
        }
      } else {
        // Use mock data if API fails
        throw new Error('API response not ok');
      }
    } catch (err) {
      console.error('Failed to fetch Telegram messages:', err);
      
      // Mock data for messages (only on first page and when not appending)
      if (!append && page === 1) {
        const mockMessages: ChatMessage[] = [
          {
            id: '1',
            sender: selectedChannelInfo?.title || selectedChannelInfo?.username || 'Channel',
            avatar: (selectedChannelInfo?.title || selectedChannelInfo?.username || 'C').charAt(0).toUpperCase(),
            message: 'New data leak detected in banking system',
            time: formatTime(new Date(Date.now() - 10 * 60000)),
            isOnline: false,
            isOwn: false,
            reactions: [
              { type: 'thumb', count: 12 },
              { type: 'heart', count: 5 },
            ],
          },
          {
            id: '2',
            sender: selectedChannelInfo?.title || selectedChannelInfo?.username || 'Channel',
            avatar: (selectedChannelInfo?.title || selectedChannelInfo?.username || 'C').charAt(0).toUpperCase(),
            message: 'Security update released for critical vulnerability',
            time: formatTime(new Date(Date.now() - 25 * 60000)),
            isOnline: false,
            isOwn: false,
            reactions: [
              { type: 'thumb', count: 8 },
              { type: 'smile', count: 3 },
            ],
          },
          {
            id: '3',
            sender: selectedChannelInfo?.title || selectedChannelInfo?.username || 'Channel',
            avatar: (selectedChannelInfo?.title || selectedChannelInfo?.username || 'C').charAt(0).toUpperCase(),
            message: 'System maintenance scheduled for tonight',
            time: formatTime(new Date(Date.now() - 60 * 60000)),
            isOnline: false,
            isOwn: false,
          },
          {
            id: '4',
            sender: selectedChannelInfo?.title || selectedChannelInfo?.username || 'Channel',
            avatar: (selectedChannelInfo?.title || selectedChannelInfo?.username || 'C').charAt(0).toUpperCase(),
            message: 'Warning: Suspicious activity detected',
            time: formatTime(new Date(Date.now() - 2 * 3600000)),
            isOnline: false,
            isOwn: false,
            reactions: [
              { type: 'heart', count: 15 },
              { type: 'thumb', count: 7 },
            ],
          },
          {
            id: '5',
            sender: selectedChannelInfo?.title || selectedChannelInfo?.username || 'Channel',
            avatar: (selectedChannelInfo?.title || selectedChannelInfo?.username || 'C').charAt(0).toUpperCase(),
            message: 'Monthly report is ready for review',
            time: formatTime(new Date(Date.now() - 5 * 3600000)),
            isOnline: false,
            isOwn: false,
            reactions: [
              { type: 'thumb', count: 4 },
            ],
          },
        ];
        
        setMessages(mockMessages);
        setTotalMessages(mockMessages.length);
        setHasMore(false);
      }
    } finally {
      if (append) {
        setLoadingMore(false);
      } else {
        setLoadingMessages(false);
      }
    }
  }, [selectedChannel, formatTime, selectedChannelInfo]);

  // Fetch messages for selected channel (initial load)
  useEffect(() => {
    if (!selectedChannel) {
      setMessages([]);
      setCurrentPage(1);
      setHasMore(true);
      return;
    }

    setCurrentPage(1);
    setHasMore(true);
    setMessages([]);
    fetchMessages(1, false);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedChannel]);

  // Handle scroll to load more messages
  useEffect(() => {
    const container = messagesContainerRef.current;
    if (!container || !hasMore || loadingMore || loadingMessages) return;

    const handleScroll = () => {
      const { scrollTop, scrollHeight, clientHeight } = container;
      // Load more when scrolled to within 100px of the bottom
      if (scrollHeight - scrollTop - clientHeight < 100) {
        const nextPage = currentPage + 1;
        setCurrentPage(nextPage);
        fetchMessages(nextPage, true);
      }
    };

    container.addEventListener('scroll', handleScroll);
    return () => {
      container.removeEventListener('scroll', handleScroll);
    };
  }, [hasMore, loadingMore, loadingMessages, currentPage, fetchMessages]);

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
                        setSelectedChannelInfo(channelDataMapRef.current.get(chat.id));
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
              {loadingMore && (
                <CircularProgress size={16} sx={{ marginInlineStart: 1 }} />
              )}
            </Box>
          </Box>

          {/* Messages */}
          <Box 
            ref={messagesContainerRef}
            sx={{ flex: 1, overflowY: 'auto', padding: 2 }}
          >
            {loadingMore && (
              <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', padding: 2 }}>
                <CircularProgress size={24} />
              </Box>
            )}
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
        </Box>
      </Box>
    </Card>
  );
};

export default ChatInterface;

