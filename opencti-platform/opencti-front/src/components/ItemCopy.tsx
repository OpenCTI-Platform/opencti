import React, { FunctionComponent, useRef, useState, useEffect } from 'react';
import { ContentCopyOutlined, Check } from '@mui/icons-material';
import Tooltip from '@mui/material/Tooltip';
import { useTheme } from '@mui/material/styles';
import IconButton from '@common/button/IconButton';
import { useFormatter } from './i18n';
import { copyToClipboard } from '../utils/utils';
import type { Theme } from './Theme';
import { truncate } from '../utils/String';
import { Box } from '@mui/material';

interface ItemCopyProps {
  content: string;
  value?: string;
  variant?: 'default' | 'inLine' | 'wrap';
  limit?: number;
  focusOnMount?: boolean;
}

const ItemCopy: FunctionComponent<ItemCopyProps> = ({
  content,
  value,
  variant = 'default',
  limit = null,
  focusOnMount = false,
}) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  const textToCopy = value || content;

  const textRef = useRef<HTMLDivElement>(null);
  const buttonRef = useRef<HTMLButtonElement>(null);
  const [isTruncated, setIsTruncated] = useState(false);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    if (focusOnMount && buttonRef.current) {
      buttonRef.current.focus();
    }
  }, [focusOnMount]);

  useEffect(() => {
    const textElement = textRef.current;
    if (textElement) {
      setIsTruncated(textElement.scrollWidth > textElement.clientWidth);
    }
  }, [content]);

  useEffect(() => {
    if (copied) {
      const timer = setTimeout(() => setCopied(false), 2000);
      return () => clearTimeout(timer);
    }
    return undefined;
  }, [copied]);

  const containerSx = () => {
    if (variant === 'inLine') {
      return {
        position: 'relative',
        padding: '2px 25px 2px 5px',
        whiteSpace: 'nowrap',
        overflow: 'hidden',
        textOverflow: 'ellipsis',
        backgroundColor: theme.palette.background.accent,
        fontFamily: 'Consolas, monaco, monospace',
        fontSize: 12,
      } as const;
    }
    if (variant === 'wrap') {
      return {
        position: 'relative',
        paddingRight: '18px',
      } as const;
    }
    return {
      position: 'relative',
      whiteSpace: 'nowrap',
      overflow: 'hidden',
      textOverflow: 'ellipsis',
    } as const;
  };

  const handleCopy = (event: React.MouseEvent) => {
    event.stopPropagation();
    event.preventDefault();
    copyToClipboard(t_i18n, textToCopy);
    setCopied(true);
  };

  const textToShow = limit ? truncate(content, limit) : content;

  const textElement = (
    <Box sx={containerSx()}>
      <Box
        ref={textRef}
        sx={{
          overflow: 'hidden',
          minWidth: 0,
          textOverflow: 'ellipsis',
          marginRight: 3,
        }}
      >
        {textToShow}
      </Box>
      <Box
        component="span"
        sx={{
          position: 'absolute',
          right: 0,
          top: variant === 'inLine' ? 0 : -3,
        }}
      >
        <Tooltip title={copied ? t_i18n('Copied') : t_i18n('Copy')}>
          <IconButton
            ref={buttonRef}
            onClick={handleCopy}
            size="small"
            aria-label={t_i18n('Copy')}
            color={copied ? 'success' : 'primary'}
            keepMui
          >
            {copied ? (
              <Check sx={{ fontSize: variant === 'inLine' ? 12 : 16 }} />
            ) : (
              <ContentCopyOutlined sx={{ fontSize: variant === 'inLine' ? 12 : 16 }} />
            )}
          </IconButton>
        </Tooltip>
      </Box>
    </Box>
  );

  return isTruncated || limit ? (
    <Tooltip title={content} placement="bottom-start">
      {textElement}
    </Tooltip>
  ) : (
    textElement
  );
};

export default ItemCopy;
