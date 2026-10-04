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
import { Tooltip, TooltipContent, TooltipTrigger } from '@filigran/design-system';
import Button from '@common/button/Button';
import Card from '@common/card/Card';
import Drawer from '@components/common/drawer/Drawer';
import { useFormatter } from '../../../../components/i18n';
import type { Theme } from '../../../../components/Theme';
import ProvenanceBadge from './ProvenanceBadge';
import ProvenanceSourceKindIcon from './ProvenanceSourceKindIcon';
import ProvenanceSourcesPanel from './ProvenanceSourcesPanel';
import { resolveProvenanceSourceLink } from './provenanceSourceLinks';
import { buildSourcesCardModel, isAssertedOnce, type ProvenanceData, sourceKindLabel, warningColor } from './provenanceUtils';
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
        x_opencti_conflicts { field field_label values { value_hash } }
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
        x_opencti_conflicts { field field_label values { value_hash } }
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
        x_opencti_conflicts { field field_label values { value_hash } }
      }
    }
  }
`;

interface ProvenanceSourcesCardContentProps {
  id: string;
  fetchKey: number;
  onOpen: () => void;
  showEmpty: boolean;
}

const ProvenanceSourcesCardContent = ({ id, fetchKey, onOpen, showEmpty }: ProvenanceSourcesCardContentProps) => {
  const theme = useTheme<Theme>();
  const { t_i18n, rd, smhd } = useFormatter();
  const data = useLazyLoadQuery<ProvenanceSourcesCardQuery>(provenanceSourcesCardQuery, { id }, { fetchPolicy: 'store-and-network', fetchKey });
  const element = data.stixObjectOrStixRelationship as ProvenanceData | null;
  const model = element ? buildSourcesCardModel(element.x_opencti_assertions, element.x_opencti_conflicts, element.corroboration_count) : null;
  if (!element) {
    return null;
  }
  if (!model) {
    return showEmpty ? (
      <Card title={t_i18n('Sources')} fullHeight={false}>
        <Typography variant="body2" data-testid="provenance-sources-empty">
          {t_i18n('No source asserted this knowledge yet.')}
        </Typography>
      </Card>
    ) : null;
  }
  return (
    <Card title={t_i18n('Sources')} fullHeight={false}>
      <Stack gap={1.5} data-testid="provenance-sources-card">
        <Stack direction="row" alignItems="center" gap={1.5} flexWrap="wrap">
          <ProvenanceBadge
            corroborationCount={element.corroboration_count}
            freshnessDays={element.freshness_days}
            stale={element.freshness_stale}
            hasConflicts={element.has_conflicts}
          />
          {element.last_asserted_at && (
            <Tooltip>
              <TooltipTrigger asChild>
                <Typography variant="body2" color="textSecondary" tabIndex={0} data-testid="provenance-last-asserted">
                  {t_i18n('Last asserted {date}', { values: { date: rd(element.last_asserted_at) } })}
                </Typography>
              </TooltipTrigger>
              <TooltipContent>{smhd(element.last_asserted_at)}</TooltipContent>
            </Tooltip>
          )}
        </Stack>
        <List dense disablePadding aria-label={t_i18n('Sources')}>
          {model.sources.map((source) => {
            const link = resolveProvenanceSourceLink(source);
            const assertedOnce = isAssertedOnce(source);
            const firstAsserted = rd(source.first_asserted_at);
            const lastAsserted = rd(source.last_asserted_at);
            const details = [
              t_i18n(sourceKindLabel(source.source_kind)),
              ...(assertedOnce
                ? [t_i18n('Asserted {date}', { values: { date: lastAsserted } })]
                : [t_i18n('First asserted {date}', { values: { date: firstAsserted } }), t_i18n('Last asserted {date}', { values: { date: lastAsserted } })]),
            ];
            const absoluteDates = assertedOnce
              ? smhd(source.last_asserted_at)
              : `${t_i18n('First asserted {date}', { values: { date: smhd(source.first_asserted_at) } })} - ${t_i18n('Last asserted {date}', { values: { date: smhd(source.last_asserted_at) } })}`;
            return (
              <ListItem
                key={source.source_id}
                disableGutters
                data-testid="provenance-source-item"
                secondaryAction={source.confidence !== null && source.confidence !== undefined ? (
                  <Typography variant="caption">{t_i18n('Confidence {confidence}', { values: { confidence: source.confidence } })}</Typography>
                ) : undefined}
              >
                <ListItemIcon sx={{ minWidth: 32 }}>
                  <ProvenanceSourceKindIcon kind={source.source_kind} color="primary" />
                </ListItemIcon>
                <ListItemText
                  primary={link ? <Link to={link}>{source.source_name}</Link> : source.source_name}
                  secondary={(
                    <Tooltip>
                      <TooltipTrigger asChild>
                        <span data-testid="provenance-source-dates">{details.join(' - ')}</span>
                      </TooltipTrigger>
                      <TooltipContent>{absoluteDates}</TooltipContent>
                    </Tooltip>
                  )}
                />
              </ListItem>
            );
          })}
        </List>
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
        <Stack direction="row" alignItems="center" justifyContent="space-between" gap={1} data-testid="provenance-sources-card-footer">
          <Typography variant="caption" color="textSecondary" data-testid="provenance-more-sources">
            {model.hiddenSourcesCount > 0
              ? t_i18n('{count, plural, one {# more source} other {# more sources}}', { values: { count: model.hiddenSourcesCount } })
              : null}
          </Typography>
          <Button variant="tertiary" size="small" onClick={onOpen} data-testid="provenance-open-sources">
            {t_i18n('View all {count, plural, one {# source} other {# sources}}', { values: { count: model.totalSourcesCount } })}
          </Button>
        </Stack>
      </Stack>
    </Card>
  );
};

interface ProvenanceSourcesCardProps {
  id: string;
  // Overview layout widget: keeps its place with an empty state when no source asserted the element yet
  showEmpty?: boolean;
}

/**
 * Sources card of entity, observable and relationship overviews: who asserted the element, when and with which
 * confidence, and the fields on which sources disagree. The Sources panel opened from the card adopts or dismisses
 * conflicting values, preserves procedures and confirms the knowledge.
 */
const ProvenanceSourcesCard = ({ id, showEmpty = false }: ProvenanceSourcesCardProps) => {
  const { t_i18n } = useFormatter();
  const [open, setOpen] = useState(false);
  const [fetchKey, setFetchKey] = useState(0);
  return (
    <>
      <Suspense fallback={null}>
        <ProvenanceSourcesCardContent id={id} fetchKey={fetchKey} onOpen={() => setOpen(true)} showEmpty={showEmpty} />
      </Suspense>
      <Drawer title={t_i18n('Sources')} open={open} onClose={() => setOpen(false)}>
        {open ? <ProvenanceSourcesPanel id={id} onChange={() => setFetchKey((key) => key + 1)} /> : null}
      </Drawer>
    </>
  );
};

export default ProvenanceSourcesCard;
