import React, { FunctionComponent } from 'react';
import purify from 'dompurify';
import parse from 'html-react-parser';
import { truncate } from '../utils/String';
import FieldOrEmpty from './FieldOrEmpty';
import { isEmptyField } from '../utils/utils';

interface HtmlDisplayProps {
  content: string | null;
  limit?: number;
}

const HtmlDisplay: FunctionComponent<HtmlDisplayProps> = ({ content, limit }) => {
  if (isEmptyField(content)) {
    return (
      <FieldOrEmpty source={content}>{content}</FieldOrEmpty>
    );
  }
  return (
    <div className='ck-content'>
      {limit ? parse(purify.sanitize(truncate(content, limit))) : parse(purify.sanitize(content))}
    </div>
  );
};

export default HtmlDisplay;
