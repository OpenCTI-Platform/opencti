import React from 'react';
import { useTheme } from '@mui/styles';
import MarkdownDisplay from '../../../components/MarkdownDisplay';
import WidgetContainer from '../../../components/dashboard/WidgetContainer';

const WidgetText = ({ variant, height = undefined, parameters = {} }) => {
  const theme = useTheme();
  const renderContent = () => {
    return (
      <div style={{ marginTop: theme.spacing(-1) }}>
        <MarkdownDisplay
          content={parameters.content}
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
      title={parameters.title}
    >
      {renderContent()}
    </WidgetContainer>
  );
};

export default WidgetText;
