import React, { useState } from "react";
import * as PropTypes from "prop-types";
import Markdown from "react-markdown";
import { truncate } from "../utils/String";
import { ExpandMore, ExpandLess } from "@material-ui/icons";
import IconButton from "@material-ui/core/IconButton";
import Grid from "@material-ui/core/Grid";

const TruncatedMarkdown = props => {
  const [expand, setExpand] = useState(false);

  const onClick = () => setExpand(!expand);

  const { source, limit } = props;
  return (
    <Grid container={true} spacing={1}>
      <Grid item xs={11}>
        <Markdown
          {...props}
          source={expand ? source : truncate(source, limit)}
        />
      </Grid>
      <Grid item xs={1}>
        <IconButton onClick={onClick}>
          {expand ? <ExpandLess /> : <ExpandMore />}
        </IconButton>
      </Grid>
    </Grid>
  );
};

TruncatedMarkdown.propTypes = {
  source: PropTypes.string,
  limit: PropTypes.number.isRequired,
};

export default TruncatedMarkdown;
