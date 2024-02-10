import React from 'react';
import MarkdownDisplay from '../../../../components/MarkdownDisplay';
import WidgetContainer from '../../../../components/dashboard/WidgetContainer';

const WidgetText = ({ variant, height = undefined, parameters = {} }) => {
  const renderContent = () => {
    return (
      <MarkdownDisplay
        content={parameters.content}
        remarkGfmPlugin={true}
        commonmark={true}
      />
    );
  };
  return (
    <WidgetContainer
      height={height}
      variant={variant}
      withoutTitle
    >
      {renderContent()}
    </WidgetContainer>
  );
};

export default WidgetText;
