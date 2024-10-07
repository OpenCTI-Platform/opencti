import React from 'react';
import MarkdownDisplay from '../../../../components/MarkdownDisplay';

const WidgetAttribute = ({ data, attribute }: { data: any, attribute: string }) => {
  console.log('data', data);
  console.log('attribute', attribute);
  const nestedAttributes = attribute.split('.');
  return (
    <div>
      {data.map((entity) => {
        const content = nestedAttributes.length > 1 ? entity[nestedAttributes[0]][nestedAttributes[1]] : entity[nestedAttributes];
        return (
          <MarkdownDisplay
            key={entity.id}
            content={content}
            remarkGfmPlugin={true}
            commonmark={true}
          />
        );
      })
      }
    </div>
  );
};

export default WidgetAttribute;
