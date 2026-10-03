import React, { Suspense, useState } from 'react';
import { graphql, useLazyLoadQuery } from 'react-relay';
import { Link } from 'react-router';
import { useTheme } from '@mui/styles';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import Stack from '@mui/material/Stack';
import Typography from '@mui/material/Typography';
import Button from '@common/button/Button';
import Card from '@common/card/Card';
import Drawer from '@components/common/drawer/Drawer';
import { useFormatter } from '../../../../components/i18n';
import type { Theme } from '../../../../components/Theme';
import ProvenanceBadge from './ProvenanceBadge';
import ProvenanceSourceKindIcon from './ProvenanceSourceKindIcon';
import ProvenanceSourcesPanel from './ProvenanceSourcesPanel';
import { resolveProvenanceSourceLink } from './provenanceSourceLinks';
import { buildSourcesCardModel, freshnessColor, type ProvenanceData, sourceKindLabel, warningColor } from './provenanceUtils';
import { ProvenanceSourcesCardQuery } from './__generated__/ProvenanceSourcesCardQuery.graphql';

const provenanceSourcesCardQuery = graphql`
  query ProvenanceSourcesCardQuery($id: String!) {
    stixObjectOrStixRelationship(id: $id) {
      ... on StixCoreObject {
        id
        entity_type
        corroboration_count
        last_asserted_at
        freshness_days
        freshness_stale
        has_conflicts
        x_opencti_assertions { source_id source_kind source_name first_asserted_at last_asserted_at assert_count confidence }
        x_opencti_conflicts { field values { value_hash } }
      }
      ... on StixCoreRelationship {
        id
        entity_type
        corroboration_count
        last_asserted_at
        freshness_days
        freshness_stale
        has_conflicts
        x_opencti_assertions { source_id source_kind source_name first_asserted_at last_asserted_at assert_count confidence }
        x_opencti_conflicts { field values { value_hash } }
      }
      ... on StixSightingRelationship {
        id
        entity_type
        corroboration_count
        last_asserted_at
        freshness_days
        freshness_stale
        has_conflicts
        x_opencti_assertions { source_id source_kind source_name first_asserted_at last_asserted_at assert_count confidence }
        x_opencti_conflicts { field values { value_hash } }
      }
    }
  }
`;

interface ProvenanceSourcesCardContentProps {
  id: string;
  fetchKey: number;
  onOpen: () => void;
}

const ProvenanceSourcesCardContent = ({ id, fetchKey, onOpen }: ProvenanceSourcesCardContentProps) => {
  const theme = useTheme<Theme>();
  const { t_i18n, fldt, nsdt } = useFormatter();
  const data = useLazyLoadQuery<ProvenanceSourcesCardQuery>(provenanceSourcesCardQuery, { id }, { fetchPolicy: 'store-and-network', fetchKey });
  const element = data.stixObjectOrStixRelationship as ProvenanceData | null;
  const model = element ? buildSourcesCardModel(element.x_opencti_assertions, element.x_opencti_conflicts, element.corroboration_count) : null;
  if (!element || !model) {
    return null;
  }
  return (
    <Card
      title={t_i18n('Sources')}
      fullHeight={false}
      action={(
        <Button variant="tertiary" size="small" onClick={onOpen} data-testid="provenance-open-sources">
          {t_i18n('View all')}
        </Button>
      )}
    >
      <Stack gap={1.5} data-testid="provenance-sources-card">
        <Stack direction="row" alignItems="center" gap={1.5} flexWrap="wrap">
          <ProvenanceBadge
            corroborationCount={element.corroboration_count}
            freshnessDays={element.freshness_days}
            stale={element.freshness_stale}
            hasConflicts={element.has_conflicts}
          />
          {element.last_asserted_at && (
            <Typography variant="body2" sx={{ color: freshnessColor(theme, element.freshness_days, element.freshness_stale) }}>
              {t_i18n('Last asserted {date}', { values: { date: fldt(element.last_asserted_at) } })}
            </Typography>
          )}
        </Stack>
        <List dense disablePadding aria-label={t_i18n('Sources')}>
          {model.sources.map((source) => {
            const link = resolveProvenanceSourceLink(source);
            const details = [
              t_i18n(sourceKindLabel(source.source_kind)),
              t_i18n('First asserted {date}', { values: { date: nsdt(source.first_asserted_at) } }),
              t_i18n('Last asserted {date}', { values: { date: nsdt(source.last_asserted_at) } }),
            ];
            return (
              <ListItem
                key={source.source_id}
                disableGutters
                data-testid="provenance-source-item"
                secondaryAction={source.confidence !== null && source.confidence !== undefined ? (
                  <Typography variant="caption">{`${t_i18n('Confidence')} ${source.confidence}`}</Typography>
                ) : undefined}
              >
                <ListItemIcon sx={{ minWidth: 32 }}>
                  <ProvenanceSourceKindIcon kind={source.source_kind} color="primary" />
                </ListItemIcon>
                <ListItemText
                  primary={link ? <Link to={link}>{source.source_name}</Link> : source.source_name}
                  secondary={details.join(' - ')}
                />
              </ListItem>
            );
          })}
        </List>
        {model.hiddenSourcesCount > 0 && (
          <div>
            <Button variant="tertiary" size="small" onClick={onOpen} data-testid="provenance-more-sources">
              {t_i18n('{count} more sources', { values: { count: model.hiddenSourcesCount } })}
            </Button>
          </div>
        )}
        {model.conflictingFields.length > 0 && (
          <Stack direction="row" alignItems="center" justifyContent="space-between" gap={1} flexWrap="wrap" data-testid="provenance-card-conflicts">
            <Typography variant="body2" sx={{ color: warningColor(theme) }}>
              {t_i18n('Sources disagree on {fields}', { values: { fields: model.conflictingFields.map((field) => t_i18n(field)).join(', ') } })}
            </Typography>
            <Button variant="secondary" size="small" onClick={onOpen} data-testid="provenance-review-conflicts">
              {t_i18n('Review conflicts')}
            </Button>
          </Stack>
        )}
      </Stack>
    </Card>
  );
};

interface ProvenanceSourcesCardProps {
  id: string;
}

/**
 * Sources card of entity, observable and relationship overviews: who asserted the element, when and with which
 * confidence, and the fields on which sources disagree. The Sources panel opened from the card adopts or dismisses
 * conflicting values, preserves procedures and confirms the knowledge. Renders nothing without provenance.
 */
const ProvenanceSourcesCard = ({ id }: ProvenanceSourcesCardProps) => {
  const { t_i18n } = useFormatter();
  const [open, setOpen] = useState(false);
  const [fetchKey, setFetchKey] = useState(0);
  return (
    <>
      <Suspense fallback={null}>
        <ProvenanceSourcesCardContent id={id} fetchKey={fetchKey} onOpen={() => setOpen(true)} />
      </Suspense>
      <Drawer title={t_i18n('Sources')} open={open} onClose={() => setOpen(false)}>
        {open ? <ProvenanceSourcesPanel id={id} onChange={() => setFetchKey((key) => key + 1)} /> : null}
      </Drawer>
    </>
  );
};

export default ProvenanceSourcesCard;
