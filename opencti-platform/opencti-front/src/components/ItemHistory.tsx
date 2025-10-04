import React, { FunctionComponent } from 'react';
import MarkdownDisplay from './MarkdownDisplay';
import { Tooltip } from '@components';
interface ItemHistoryProps {
  username: string,
  message: string,
}

const ItemHistory: FunctionComponent<ItemHistoryProps> = ({
  username,
  message,
}) => {
  return (
    <Tooltip
      title={(
        <MarkdownDisplay
          content={`\`${username}\` ${message}`}
          remarkGfmPlugin
          commonmark
        />
      )}
    >
      <div style={{ textOverflow: 'ellipsis', overflow: 'hidden', whiteSpace: 'nowrap' }}>
        <MarkdownDisplay
          content={`\`${username}\` ${message}`}
          remarkGfmPlugin
          commonmark
        />
      </div>
    </Tooltip>
  );
};

export default ItemHistory;
