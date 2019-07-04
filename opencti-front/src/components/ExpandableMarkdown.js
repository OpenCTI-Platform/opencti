import React, { useState } from 'react';
import * as PropTypes from 'prop-types';
import Markdown from 'react-markdown';
import { ExpandMore, ExpandLess } from '@material-ui/icons';
import IconButton from '@material-ui/core/IconButton';
import Grid from '@material-ui/core/Grid';
import { truncate } from '../utils/String';

const ExpandableMarkdown = (props) => {
  const [expand, setExpand] = useState(false);

  const onClick = () => setExpand(!expand);

  const { source, limit } = props;
  const shouldBeTruncated = (source || '').length > limit;

  return (
    <Grid container={true} spacing={1}>
      <Grid item xs={shouldBeTruncated ? 11 : 12}>
        <Markdown
          {...props}
          source={expand ? source : truncate(source, limit)}
        />
      </Grid>
      {shouldBeTruncated && (
        <Grid item xs={1}>
          <IconButton onClick={onClick}>
            {expand ? <ExpandLess /> : <ExpandMore />}
          </IconButton>
        </Grid>
      )}
    </Grid>
  );
};

ExpandableMarkdown.propTypes = {
  source: PropTypes.string.isRequired,
  limit: PropTypes.number.isRequired,
};

export default ExpandableMarkdown;
