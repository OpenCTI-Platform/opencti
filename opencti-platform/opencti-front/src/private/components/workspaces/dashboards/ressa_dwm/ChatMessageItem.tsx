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

// Function to normalize unicode double quotes to standard double quote
const normalizeUnicodeQuotes = (text: string): string => {
  if (!text || typeof text !== 'string') {
    return text;
  }
  
  // First, decode any unicode escape sequences (like \u201C)
  let decodedText = text.replace(/\\u([0-9A-F]{4})/gi, (match, hex) => {
    const codePoint = parseInt(hex, 16);
    // Check if it's a unicode quotation mark character
    if ((codePoint >= 0x201C && codePoint <= 0x201F) || 
        (codePoint >= 0x2033 && codePoint <= 0x2037) ||
        codePoint === 0x275D || codePoint === 0x275E ||
        (codePoint >= 0x301D && codePoint <= 0x301F)) {
      return '"';
    }
    return match;
  });
  
  // Replace various unicode double quote characters with standard "
  // Using unicode ranges for comprehensive coverage
  return decodedText
    .replace(/[\u201C\u201D\u201E\u201F]/g, '"')  // General quotation marks (U+201C-201F)
    .replace(/[\u2033\u2036\u2037]/g, '"')       // Prime quotation marks (U+2033, U+2036-2037)
    .replace(/[\u275D\u275E]/g, '"')             // Heavy quotation marks (U+275D-275E)
    .replace(/[\u301D\u301E\u301F]/g, '"');      // Additional quotation marks (U+301D-301F)
};

// Function to remove unwanted whitespace characters from text
const removeWhitespaceChars = (text: string): string => {
  if (!text || typeof text !== 'string') {
    return text;
  }
  
  // Remove newline (\n), carriage return (\r), tab (\t), and other control characters
  return text
    .replace(/\n/g, '')      // Remove newline
    .replace(/\r/g, '')      // Remove carriage return
    .replace(/\t/g, '')      // Remove tab
    .replace(/\f/g, '')      // Remove form feed
    .replace(/\v/g, '')      // Remove vertical tab
    .replace(/[\u0000-\u001F\u007F-\u009F]/g, ''); // Remove other control characters
};

// Function to replace nested quotes inside strings with single quotes
const replaceNestedQuotes = (text: string): string => {
  if (!text || typeof text !== 'string') {
    return text;
  }
  
  let result = '';
  let inString = false;
  let escapeNext = false;
  
  for (let i = 0; i < text.length; i++) {
    const char = text[i];
    
    if (escapeNext) {
      result += char;
      escapeNext = false;
      continue;
    }
    
    if (char === '\\') {
      result += char;
      escapeNext = true;
      continue;
    }
    
    if (char === '"') {
      if (!inString) {
        // Opening quote - start the string
        inString = true;
        result += char;
      } else {
        // Closing quote - check if it should close the string
        const nextChars = text.substring(i + 1).trim();
        if (nextChars.startsWith(',') || nextChars.startsWith(':') || nextChars.startsWith('}') || nextChars.startsWith(']')) {
          // This closes the string
          inString = false;
          result += char;
        } else {
          // This is a nested quote inside the string - replace with '
          result += "'";
        }
      }
    } else {
      result += char;
    }
  }
  
  return result;
};

// Function to check and format JSON
const formatJsonIfNeeded = (text: string): { isJson: boolean; formattedText: string; remainingText?: string } => {
  if (!text || typeof text !== 'string') {
    return { isJson: false, formattedText: text };
  }

  // Debug: log original text to check for unicode quotes
  // const hasUnicodeQuotes = /[\u201C-\u201F\u2033\u2036\u2037\u275D\u275E\u301D-\u301F]/.test(text);
  // if (hasUnicodeQuotes) {
  //   console.log('Found unicode quotes in text:', text);
  // }
  
  const normalizedText = normalizeUnicodeQuotes(text);
  const cleanedText = removeWhitespaceChars(normalizedText);
  const replacedQuotes = replaceNestedQuotes(cleanedText);
  // Debug: check if normalization changed anything
  // if (normalizedText !== text) {
  //   console.log('Text normalized:', { original: text, normalized: normalizedText });
  // }
  const trimmedText = replacedQuotes.trim();
  
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
          if (!inString) {
            // Opening quote - start the string
            inString = true;
          } else {
            // Closing quote - only close if followed by , or : or } or ]
            const nextChars = trimmedText.substring(i + 1).trim();
            if (nextChars.startsWith(',') || nextChars.startsWith(':') || nextChars.startsWith('}') || nextChars.startsWith(']')) {
              inString = false;
            }
            // If not followed by , or : or } or ], keep the string open
          }
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
          } catch(e) {
            // If parsing still failed, JSON is not valid
            // console.log(e.message)
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

