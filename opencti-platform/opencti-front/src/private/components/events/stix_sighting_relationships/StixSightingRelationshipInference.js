import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import withStyles from '@mui/styles/withStyles';
import withTheme from '@mui/styles/withTheme';
import Typography from '@mui/material/Typography';
import Paper from '@mui/material/Paper';
import ForceGraph2D from 'react-force-graph-2d';
import Markdown from 'react-markdown';
import { withRouter } from 'react-router-dom';
import remarkGfm from 'remark-gfm';
import remarkParse from 'remark-parse';
import inject18n from '../../../../components/i18n';
import {
  buildGraphData,
  linkPaint,
  nodeAreaPaint,
  nodePaint,
} from '../../../../utils/Graph';
import { resolveLink } from '../../../../utils/Entity';

const styles = () => ({
  container: {
    position: 'relative',
  },
  paper: {
    width: '100%',
    position: 'relative',
    height: 500,
    minHeight: 500,
    margin: '10px 0 0 0',
    padding: '15px',
    borderRadius: 6,
    textAlign: 'center',
  },
});

class StixSightingRelationshipInference extends Component {
  constructor(props) {
    super(props);
    this.initialized = false;
    this.graph = React.createRef();
  }

  initialize() {
    if (this.initialized) return;
    if (this.graph && this.graph.current) {
      this.graph.current.d3Force('link').distance(80);
      // eslint-disable-next-line @typescript-eslint/no-this-alias
      const currentContext = this;
      setTimeout(
        () => currentContext.graph
          && currentContext.graph.current
          && currentContext.graph.current.zoomToFit(0, 50),
        500,
      );
      this.initialized = true;
    }
  }

  componentDidMount() {
    this.initialize();
  }

  handleLinkClick(link) {
    const permalink = `${resolveLink(link.source.entity_type)}/${
      link.source_id
    }/knowledge/${
      link.entity_type === 'stix-sighting-relationship'
        ? 'sightings'
        : 'relations'
    }/${link.id}`;
    this.props.history.push(permalink);
  }

  render() {
    const {
      t,
      classes,
      inference,
      theme,
      stixSightingRelationship,
      paddingRight,
    } = this.props;
    const width = window.innerWidth - (paddingRight ? 450 : 250);
    const graphObjects = [
      R.assoc('inferred', true, stixSightingRelationship),
      stixSightingRelationship.from,
      stixSightingRelationship.to,
      ...inference.explanation,
      ...R.pipe(
        R.filter((n) => n.from && n.to),
        R.map((n) => [n.from, n.to]),
        R.flatten,
      )(inference.explanation),
    ];
    const graphData = buildGraphData(graphObjects, [], t);
    return (
      <Paper
        classes={{ root: classes.paper }}
        variant="outlined"
        key={inference.rule.id}
      >
        <Typography variant="h3" gutterBottom={true}>
          {t(inference.rule.name)}
        </Typography>
        <Markdown
          remarkPlugins={[remarkGfm, remarkParse]}
          parserOptions={{ commonmark: true }}
          className="markdown"
        >
          {inference.rule.description}
        </Markdown>
        <ForceGraph2D
          ref={this.graph}
          width={width}
          height={440}
          graphData={graphData}
          nodeRelSize={4}
          nodeCanvasObject={(node, ctx) => nodePaint(node, node.color, ctx, false)
          }
          nodePointerAreaPaint={nodeAreaPaint}
          linkCanvasObjectMode={() => 'after'}
          linkCanvasObject={(link, ctx) => linkPaint(link, ctx, theme.palette.text.primary)
          }
          linkColor={(link) => (link.inferred
            ? theme.palette.secondary.main
            : theme.palette.primary.main)
          }
          linkDirectionalParticles={(link) => (link.inferred ? 20 : 0)}
          linkDirectionalParticleWidth={2}
          linkDirectionalParticleSpeed={() => 0.002}
          linkDirectionalArrowLength={3}
          linkDirectionalArrowRelPos={0.99}
          onLinkClick={this.handleLinkClick.bind(this)}
          enableZoomInteraction={false}
          enablePanInteraction={false}
          enableNodeDrag={false}
        />
      </Paper>
    );
  }
}

StixSightingRelationshipInference.propTypes = {
  inference: PropTypes.object,
  paddingRight: PropTypes.bool,
  stixSightingRelationship: PropTypes.object,
};

export default R.compose(
  inject18n,
  withStyles(styles),
  withRouter,
  withTheme,
)(StixSightingRelationshipInference);
