import React from 'react';
import { Box, Typography, Avatar, Paper, IconButton } from '@mui/material';
import { ThumbUp, Favorite, SentimentSatisfied, MoreVert } from '@mui/icons-material';
import { useTheme } from '@mui/styles';
import { Prism as SyntaxHighlighter } from 'react-syntax-highlighter';
import { a11yDark, coy } from 'react-syntax-highlighter/dist/esm/styles/prism';
import JSON5 from 'json5';
import type { Theme } from '../../../../../components/Theme';

export interface ChatMessage {
  id: string;
  sender: string;
  avatar: string;
  message: string;
  time: string;
  isOnline?: boolean;
  isOwn?: boolean; // Whether the message is from the current user
  reactions?: { type: string; count: number }[];
  attachment?: string;
}

interface ChatMessageItemProps {
  message: ChatMessage;
}

// Function to check and format JSON
const formatJsonIfNeeded = (text: string): { isJson: boolean; formattedText: string; remainingText?: string } => {
  if (!text || typeof text !== 'string') {
    return { isJson: false, formattedText: text };
  }

  const trimmedText = text.trim();
  
  // First, try to parse the entire text (first with standard JSON, then with JSON5)
  try {
    const parsed = JSON.parse(trimmedText);
    const formatted = JSON.stringify(parsed, null, 2);
    return { isJson: true, formattedText: formatted };
  } catch {
    // If JSON.parse failed, try with JSON5 (for non-standard JSON)
    try {
      const parsed = JSON5.parse(trimmedText);
      const formatted = JSON.stringify(parsed, null, 2);
      return { isJson: true, formattedText: formatted };
    } catch {
      // If the entire text is not JSON, try to extract JSON from the beginning of the text
      if (trimmedText.startsWith('{') || trimmedText.startsWith('[')) {
      let jsonEndIndex = -1;
      let braceCount = 0;
      let bracketCount = 0;
      let inString = false;
      let escapeNext = false;
      
      // Find the end of JSON object or array
      for (let i = 0; i < trimmedText.length; i++) {
        const char = trimmedText[i];
        
        if (escapeNext) {
          escapeNext = false;
          continue;
        }
        
        if (char === '\\') {
          escapeNext = true;
          continue;
        }
        
        if (char === '"' && !escapeNext) {
          inString = !inString;
          continue;
        }
        
        if (!inString) {
          if (char === '{') {
            braceCount++;
          } else if (char === '}') {
            braceCount--;
            if (braceCount === 0 && trimmedText.startsWith('{')) {
              jsonEndIndex = i + 1;
              break;
            }
          } else if (char === '[') {
            bracketCount++;
          } else if (char === ']') {
            bracketCount--;
            if (bracketCount === 0 && trimmedText.startsWith('[')) {
              jsonEndIndex = i + 1;
              break;
            }
          }
        }
      }
      
      // If we found the end of JSON
      if (jsonEndIndex > 0) {
        const jsonPart = trimmedText.substring(0, jsonEndIndex);
        const remainingPart = trimmedText.substring(jsonEndIndex).trim();
        
        try {
          // First try with standard JSON
          const parsed = JSON.parse(jsonPart);
          const formatted = JSON.stringify(parsed, null, 2);
          return { 
            isJson: true, 
            formattedText: formatted,
            remainingText: remainingPart || undefined
          };
        } catch {
          // If JSON.parse failed, try with JSON5 (for non-standard JSON)
          try {
            const parsed = JSON5.parse(jsonPart);
            const formatted = JSON.stringify(parsed, null, 2);
            return { 
              isJson: true, 
              formattedText: formatted,
              remainingText: remainingPart || undefined
            };
          } catch {
            // If parsing still failed, JSON is not valid
          }
        }
      }
      }
    }
  }
  
  return { isJson: false, formattedText: text };
};

const ChatMessageItem: React.FC<ChatMessageItemProps> = ({ message }) => {
  const theme = useTheme<Theme>();
  const isDark = theme.palette.mode === 'dark';
  const isOwn = message.isOwn || false;
  const { isJson, formattedText, remainingText } = formatJsonIfNeeded(message.message);

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
            <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1, width: '100%' }}>
              {isJson ? (
                <>
                  <Box sx={{ width: '100%', overflow: 'auto', maxHeight: '400px' }}>
                    <SyntaxHighlighter
                      language="json"
                      style={isDark ? a11yDark : coy}
                      customStyle={{
                        margin: 0,
                        padding: '8px',
                        borderRadius: '4px 4px 0 0',
                        fontSize: '0.75rem',
                        backgroundColor: 'transparent',
                      }}
                    >
                      {formattedText}
                    </SyntaxHighlighter>
                  </Box>
                  {remainingText && (
                    <Typography variant="body2" sx={{ fontSize: '0.875rem', color: theme.palette.text?.primary }}>
                      {remainingText}
                    </Typography>
                  )}
                </>
              ) : (
                <Typography variant="body2" sx={{ fontSize: '0.875rem', color: theme.palette.text?.primary }}>
                  {message.message}
                </Typography>
              )}
            </Box>
            <IconButton size="small" sx={{ color: theme.palette.text?.primary }}>
              <MoreVert fontSize="small" />
            </IconButton>
          </Paper>
        ) : (
          <Paper
            sx={{
              padding: isJson ? 0 : 1.5,
              backgroundColor: isOwn
                ? (isDark ? 'rgba(25, 118, 210, 0.2)' : '#e3f2fd')
                : (theme.palette.background?.paper || theme.palette.background?.default),
              borderRadius: 2,
              marginBottom: message.reactions ? 1 : 0,
              overflow: 'hidden',
            }}
          >
            {isJson ? (
              <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
                <Box sx={{ width: '100%', overflow: 'auto', maxHeight: '400px' }}>
                  <SyntaxHighlighter
                    language="json"
                    style={isDark ? a11yDark : coy}
                    customStyle={{
                      margin: 0,
                      padding: '12px',
                      borderRadius: '8px 8px 0 0',
                      fontSize: '0.75rem',
                      backgroundColor: 'transparent',
                    }}
                  >
                    {formattedText}
                  </SyntaxHighlighter>
                </Box>
                {remainingText && (
                  <Typography variant="body2" sx={{ fontSize: '0.875rem', color: theme.palette.text?.primary, padding: '0 12px 12px 12px' }}>
                    {remainingText}
                  </Typography>
                )}
              </Box>
            ) : (
              <Typography variant="body2" sx={{ fontSize: '0.875rem', color: theme.palette.text?.primary }}>
                {message.message}
              </Typography>
            )}
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
                {reaction.type === 'thumb' && <ThumbUp style={{ width: '24px', height: '24px', color: '#1976d2' }} />}
                {reaction.type === 'heart' && <Favorite style={{ width: '24px', height: '24px', color: '#f44336' }} />}
                {reaction.type === 'smile' && <SentimentSatisfied style={{ width: '24px', height: '24px', color: '#ff9800' }} />}
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

