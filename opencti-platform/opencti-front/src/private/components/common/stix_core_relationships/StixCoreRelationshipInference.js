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
import { isEmptyField } from '../../../../utils/utils';

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

class StixCoreRelationshipInference extends Component {
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
    const { t, classes, inference, theme, stixCoreRelationship, paddingRight } = this.props;
    const width = window.innerWidth - (paddingRight ? 450 : 250);
    const stixRelationship = { ...stixCoreRelationship };
    // Complete the relationship if needed
    if (isEmptyField(stixRelationship.from)) {
      stixRelationship.from = { id: stixCoreRelationship.fromId, name: 'Restricted', entity_type: stixCoreRelationship.fromType, parent_types: [] };
    }
    if (isEmptyField(stixRelationship.to)) {
      stixRelationship.to = { id: stixCoreRelationship.toId, name: 'Restricted', relationship_type: stixCoreRelationship.toType, parent_types: [] };
    }
    // Complete the explanations if needed
    const explanations = inference.explanation.map((ex) => {
      const data = { ...ex };
      if (isEmptyField(ex.from)) {
        data.from = { id: ex.fromId, name: 'Restricted', entity_type: ex.fromType, parent_types: [] };
      }
      if (isEmptyField(ex.to)) {
        data.to = { id: ex.toId, name: 'Restricted', relationship_type: ex.toType, parent_types: [] };
      }
      return data;
    });
    // Build the graph objects
    const graphObjects = [
      R.assoc('inferred', true, stixRelationship),
      stixRelationship.from,
      stixRelationship.to,
      ...explanations.filter((n) => n !== null),
      ...explanations.filter((n) => n !== null).map((n) => [n.from, n.to]).flat(),
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
          height={400}
          graphData={graphData}
          nodeRelSize={4}
          nodeCanvasObject={(node, ctx) => nodePaint(
            {
              selected: theme.palette.secondary.main,
              inferred: theme.palette.warning.main,
            },
            node,
            node.color,
            ctx,
            false,
          )
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

StixCoreRelationshipInference.propTypes = {
  inference: PropTypes.object,
  paddingRight: PropTypes.bool,
  stixCoreRelationship: PropTypes.object,
};

export default R.compose(
  inject18n,
  withStyles(styles),
  withRouter,
  withTheme,
)(StixCoreRelationshipInference);
