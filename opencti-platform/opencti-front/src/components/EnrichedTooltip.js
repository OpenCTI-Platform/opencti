import React from 'react';
import * as PropTypes from 'prop-types';
import Typography from '@mui/material/Typography';
import Tooltip from '@mui/material/Tooltip';
import Markdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import remarkParse from 'remark-parse';
import { useTheme } from '@mui/styles';
import makeStyles from '@mui/styles/makeStyles';
import { truncate } from '../utils/String';
import { MarkDownComponents } from './ExpandableMarkdown';

const useStyles = makeStyles((theme) => ({
  tooltip: {
    minWidth: 500,
    maxWidth: 500,
    border: `1px solid ${theme.palette.primary.main}`,
    padding: 15,
  },
}));

const EnrichedTooltip = (props) => {
  const { icon, title, subtitle, description, children } = props;
  const theme = useTheme();
  const classes = useStyles();
  return (
    <Tooltip
      classes={{ tooltip: classes.tooltip }}
      title={
        <React.Fragment>
          <div style={{ float: 'left', marginRight: 15 }}>{icon}</div>
          <div style={{ float: 'left' }}>
            <Typography variant="h1" style={{ margin: 0 }}>{title}</Typography>
          </div>
          <div className="clearfix" />
          <Typography variant="subtitle1">{subtitle}</Typography>
          <Markdown
            remarkPlugins={[remarkGfm, remarkParse]}
            parserOptions={{ commonmark: true }}
            components={MarkDownComponents(theme)}
            className="markdown"
          >
            {truncate(description, 300)}
          </Markdown>
        </React.Fragment>
      }
    >
      {children}
    </Tooltip>
  );
};

EnrichedTooltip.propTypes = {
  icon: PropTypes.node,
  title: PropTypes.string,
  subtitle: PropTypes.string,
  description: PropTypes.string,
  children: PropTypes.node,
};

export default EnrichedTooltip;
