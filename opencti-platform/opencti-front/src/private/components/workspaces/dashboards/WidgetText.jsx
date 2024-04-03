import React from 'react';
import MarkdownDisplay from '../../../../components/MarkdownDisplay';
import WidgetContainer from '../../../../components/dashboard/WidgetContainer';

const WidgetText = ({ variant, height = undefined, parameters = {} }) => {
  const renderContent = () => {
    return (
      <div style={{ marginTop: -20 }}>
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
      withoutTitle={true}
    >
      {renderContent()}
    </WidgetContainer>
  );
};

export default WidgetText;
