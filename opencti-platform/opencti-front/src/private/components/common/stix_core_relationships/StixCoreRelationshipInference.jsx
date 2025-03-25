import React, { useMemo, useRef } from 'react';
import { Typography, Paper } from '@mui/material';
import { useNavigate } from 'react-router-dom';
import { useFormatter } from '../../../../components/i18n';
import { isEmptyField } from '../../../../utils/utils';
import MarkdownDisplay from '../../../../components/MarkdownDisplay';
import useGraphParser from '../../../../components/graph/utils/useGraphParser';
import SimpleGraph2D from '../../../../components/graph/SimpleGraph2D';
import { resolveLink } from '../../../../utils/Entity';

const StixCoreRelationshipInference = ({ stixRelationship, inference }) => {
  const navigate = useNavigate();
  const { t_i18n } = useFormatter();
  const { buildGraphData } = useGraphParser();
  const parentRef = useRef(null);

  const handleLinkClick = ({ source, entity_type, source_id, id }) => {
    const linkBasePath = resolveLink(source.entity_type);
    const linkEndpoint = entity_type === 'stix-sighting-relationship' ? 'sightings' : 'relations';
    navigate(`${linkBasePath}/${source_id}/knowledge/${linkEndpoint}/${id}`);
  };

  const graphData = useMemo(() => {
    const relationship = { ...stixRelationship };

    // Complete the relationship if needed
    if (isEmptyField(stixRelationship.from)) {
      relationship.from = {
        id: stixRelationship.fromId,
        name: 'Restricted',
        entity_type: stixRelationship.fromType,
        parent_types: [],
      };
    }
    if (isEmptyField(stixRelationship.to)) {
      relationship.to = {
        id: stixRelationship.toId,
        name: 'Restricted',
        entity_type: stixRelationship.toType,
        parent_types: [],
      };
    }

    // Complete the explanations if needed
    const explanations = inference.explanation.map((ex) => {
      const data = { ...ex };
      if (isEmptyField(ex.from)) {
        data.from = {
          id: ex.fromId,
          name: 'Restricted',
          entity_type: ex.fromType,
          parent_types: [],
        };
      }
      if (isEmptyField(ex.to)) {
        data.to = {
          id: ex.toId,
          name: 'Restricted',
          entity_type: ex.toType,
          parent_types: [],
        };
      }
      return data;
    });

    // Build the graph objects
    return buildGraphData([
      { ...relationship, inferred: true },
      relationship.from,
      relationship.to,
      ...explanations.filter((n) => n !== null),
      ...explanations
        .filter((n) => n !== null)
        .map((n) => [n.from, n.to])
        .flat(),
    ], {});
  });

  return (
    <Paper
      sx={{
        width: '100%',
        position: 'relative',
        height: 500,
        minHeight: 500,
        marginTop: 1,
        padding: '15px',
        borderRadius: 1,
        textAlign: 'center',
      }}
      variant="outlined"
      key={inference.rule.id}
    >
      <Typography variant="h3" gutterBottom={true}>
        {t_i18n(inference.rule.name)}
      </Typography>
      <MarkdownDisplay
        content={inference.rule.description}
        remarkGfmPlugin={true}
        commonmark={true}
      />
      <div ref={parentRef} style={{ height: 430 }}>
        <SimpleGraph2D
          onReady={(graphRef) => {
            graphRef.d3Force('link').distance(80);
            graphRef.zoomToFit(200, 140);
          }}
          parentRef={parentRef}
          graphData={graphData}
          enableNodeDrag={false}
          enablePanInteraction={false}
          enableZoomInteraction={false}
          onLinkClick={handleLinkClick}
        />
      </div>
    </Paper>
  );
};

export default StixCoreRelationshipInference;
