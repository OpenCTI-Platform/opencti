import React, { useState } from 'react';
import { ExpandLess, ExpandMore } from '@mui/icons-material';
import IconButton from '@common/button/IconButton';
import { truncate } from '../utils/String';

interface ExpandablePreProps {
  source: string | null | undefined;
  limit: number;
}

const ExpandablePre = ({ source, limit }: ExpandablePreProps) => {
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
      <pre style={{ margin: 0 }}>{expand ? source : truncate(source, limit)}</pre>
    </div>
  );
};

export default ExpandablePre;
