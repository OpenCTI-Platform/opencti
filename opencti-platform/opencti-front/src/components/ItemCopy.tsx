import React, { FunctionComponent, useRef, useState, useEffect } from 'react';
import { ContentCopyOutlined, Check } from '@mui/icons-material';
import makeStyles from '@mui/styles/makeStyles';
import Tooltip from '@mui/material/Tooltip';
import IconButton from '@common/button/IconButton';
import { useFormatter } from './i18n';
import { copyToClipboard } from '../utils/utils';
import type { Theme } from './Theme';
import { truncate } from '../utils/String';
import { Box } from '@mui/material';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles<Theme>((theme) => ({
  containerInline: {
    position: 'relative',
    padding: '2px 25px 2px 5px',
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    backgroundColor: theme.palette.background.accent,
    fontFamily: 'Consolas, monaco, monospace',
    fontSize: 12,
  },
  containerWrap: {
    position: 'relative',
    paddingRight: 18,
  },
  container: {
    position: 'relative',
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
  icon: {
    position: 'absolute',
    right: 0,
    top: -3,
  },
  iconInline: {
    position: 'absolute',
    right: 0,
    top: 0,
  },
}));

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
  const classes = useStyles();
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

  const classNameVariant = () => {
    if (variant === 'inLine') return classes.containerInline;
    if (variant === 'wrap') return classes.containerWrap;
    return classes.container;
  };

  const handleCopy = (event: React.MouseEvent) => {
    event.stopPropagation();
    event.preventDefault();
    copyToClipboard(t_i18n, textToCopy);
    setCopied(true);
  };

  const textToShow = limit ? truncate(content, limit) : content;

  const textElement = (
    <div className={classNameVariant()}>
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
      <span className={variant === 'inLine' ? classes.iconInline : classes.icon}>
        <Tooltip title={copied ? t_i18n('Copied') : t_i18n('Copy')}>
          <IconButton
            ref={buttonRef}
            onClick={handleCopy}
            size="small"
            aria-label={t_i18n('Copy')}
            color={copied ? 'success' : 'primary'}
          >
            {copied ? (
              <Check sx={{ fontSize: variant === 'inLine' ? 12 : 16 }} />
            ) : (
              <ContentCopyOutlined sx={{ fontSize: variant === 'inLine' ? 12 : 16 }} />
            )}
          </IconButton>
        </Tooltip>
      </span>
    </div>
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
