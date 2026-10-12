import React from 'react';
import { useNavigate } from 'react-router';
import { Chip, Text } from '@filigran/design-system';
import { Box } from '@mui/material';
import ItemIcon from '../../../../components/ItemIcon';
import { useFormatter } from '../../../../components/i18n';
import { resolveLink } from '../../../../utils/Entity';
import { GRAPH_FEATURE_FAMILY_LABELS } from './graphAnalyticsUtils';

export interface GraphEvidenceEntity {
  readonly id: string;
  readonly entity_type: string;
  readonly representative: { readonly main: string };
}

export interface GraphEvidenceFamily {
  readonly family: string;
  readonly entities: ReadonlyArray<GraphEvidenceEntity>;
}

interface GraphSimilarityEvidenceProps {
  evidence: ReadonlyArray<GraphEvidenceFamily>;
  // number of chips shown per family before the "+N" counter
  maxPerFamily?: number;
  dense?: boolean;
}

/** Shared elements behind a similarity score or a cluster, grouped by family, each one a link to the entity. */
const GraphSimilarityEvidence = ({ evidence, maxPerFamily = 8, dense = false }: GraphSimilarityEvidenceProps) => {
  const { t_i18n } = useFormatter();
  const navigate = useNavigate();
  if (evidence.length === 0) {
    return <Text variant="content-compact">{t_i18n('No shared element you can access')}</Text>;
  }
  return (
    <Box sx={{ display: 'flex', flexDirection: 'column', gap: dense ? 0.5 : 1 }} data-testid="graph-similarity-evidence">
      {evidence.map(({ family, entities }) => {
        const shown = entities.slice(0, maxPerFamily);
        const hidden = entities.length - shown.length;
        return (
          <Box key={family} sx={{ display: 'flex', alignItems: 'center', flexWrap: 'wrap', gap: 0.5 }}>
            <Text variant="content-compact-medium" style={{ minWidth: 130 }}>
              {`${t_i18n(GRAPH_FEATURE_FAMILY_LABELS[family] ?? family)} (${entities.length})`}
            </Text>
            {shown.map((entity) => (
              <Chip
                key={entity.id}
                label={entity.representative.main}
                startIcon={<ItemIcon type={entity.entity_type} size="small" />}
                onClick={() => navigate(`${resolveLink(entity.entity_type)}/${entity.id}`)}
              />
            ))}
            {hidden > 0 && <Text variant="content-caption" as="span">{t_i18n('and {count} more', { values: { count: hidden } })}</Text>}
          </Box>
        );
      })}
    </Box>
  );
};

export default GraphSimilarityEvidence;
