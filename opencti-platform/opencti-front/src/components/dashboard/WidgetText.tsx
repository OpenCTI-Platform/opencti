import React, { CSSProperties, ReactNode } from 'react';
import MarkdownDisplay from '../markdownDisplay/MarkdownDisplay';
import WidgetContainer from './WidgetContainer';
import { Box } from '@mui/material';

interface WidgetTextProps {
  variant?: string;
  height?: CSSProperties['height'];
  popover?: ReactNode;
  parameters?: {
    title?: string | null;
    content?: string | null;
  } | null;
}

const WidgetText = ({
  variant,
  height = undefined,
  parameters = {},
  popover,
}: WidgetTextProps) => {
  return (
    <WidgetContainer
      height={height}
      variant={variant}
      title={parameters?.title ?? ''}
      action={popover}
    >
      <Box
        sx={{
          '& h1:first-child, & h2:first-child, & h3:first-child, & h4:first-child, & h5:first-child, & h6:first-child': {
            marginTop: 0,
          },
        }}
      >
        <MarkdownDisplay
          content={parameters?.content}
          remarkGfmPlugin={true}
          commonmark={true}
        />
      </Box>
    </WidgetContainer>
  );
};

export default WidgetText;
