import React, { FunctionComponent, useState } from 'react';
import { ExpandLess, ExpandMore } from '@mui/icons-material';
import IconButton from '@common/button/IconButton';
import { emptyFilled, truncate } from '../utils/String';
import MarkdownDisplay from './MarkdownDisplay';

interface ExpandableMarkdownProps {
  source?: string | null;
  limit: number;
  removeLinks?: boolean;
}

const ExpandableMarkdown: FunctionComponent<ExpandableMarkdownProps> = ({
  source,
  limit,
  removeLinks = false,
}) => {
  const [expand, setExpand] = useState(false);
  const onClick = () => setExpand(!expand);
  const shouldBeTruncated = (source || '').length > limit;
  return (
    <div style={{ position: 'relative' }}>
      {shouldBeTruncated && (
        <div style={{ position: 'absolute', top: -32, right: 0 }}>
          <IconButton onClick={onClick}>
            {expand ? <ExpandLess /> : <ExpandMore />}
          </IconButton>
        </div>
      )}
      <div style={{ overflowX: 'auto' }}>
        <MarkdownDisplay
          content={expand ? emptyFilled(source) : truncate(source, limit)}
          remarkGfmPlugin={true}
          commonmark={true}
          removeLinks={removeLinks}
        />
      </div>
    </div>
  );
};

export default ExpandableMarkdown;
