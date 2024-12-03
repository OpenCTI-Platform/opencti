import React, { CSSProperties } from 'react';
import { useTheme } from '@mui/styles';
import MarkdownDisplay from '../MarkdownDisplay';
import WidgetContainer from './WidgetContainer';
import type { Theme } from '../Theme';

interface WidgetTextProps {
  variant: string
  height?: CSSProperties['height']
  parameters?: {
    title?: string | null
    content?: string | null
  } | null
}

const WidgetText = ({
  variant,
  height = undefined,
  parameters = {},
}: WidgetTextProps) => {
  const theme = useTheme<Theme>();
  const renderContent = () => {
    return (
      <div style={{ marginTop: theme.spacing(-1) }}>
        <MarkdownDisplay
          content={parameters?.content ?? ''}
          remarkGfmPlugin={true}
          commonmark={true}
        />
      </div>
    );
  };
  return (
    <WidgetContainer
      height={height}
      variant={variant}
      title={parameters?.title ?? ''}
    >
      {renderContent()}
    </WidgetContainer>
  );
};

export default WidgetText;
