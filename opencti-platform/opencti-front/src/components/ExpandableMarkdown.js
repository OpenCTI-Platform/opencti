import React, { useState } from 'react';
import * as PropTypes from 'prop-types';
import Markdown from 'react-markdown';
import { ExpandMore, ExpandLess } from '@material-ui/icons';
import IconButton from '@material-ui/core/IconButton';
import { truncate } from '../utils/String';

const ExpandableMarkdown = (props) => {
  const [expand, setExpand] = useState(false);

  const onClick = () => setExpand(!expand);

  const { source, limit } = props;
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
      <div style={{ paddingTop: 10 }}>
        <Markdown
          {...props}
          source={expand ? source : truncate(source, limit)}
        />
      </div>
      <div className="clearfix" />
    </div>
  );
};

ExpandableMarkdown.propTypes = {
  source: PropTypes.string.isRequired,
  limit: PropTypes.number.isRequired,
};

export default ExpandableMarkdown;
