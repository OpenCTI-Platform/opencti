import React from 'react';
import { Link } from 'react-router';
import { Chip, Text } from '@filigran/design-system';
import { Alert, Box, Table, TableBody, TableCell, TableHead, TableRow } from '@mui/material';
import Grid from '@mui/material/Grid2';
import Button from '@common/button/Button';
import Card from '@common/card/Card';
import WidgetDistributionList from '../../../../components/dashboard/WidgetDistributionList';
import { useFormatter } from '../../../../components/i18n';
import { resolveLink } from '../../../../utils/Entity';
import TimeMachineSummaryCard from './TimeMachineSummaryCard';
import {
  entityChangesPath,
  LANDSCAPE_GROUP_BY_RELATIONSHIP_TYPE,
  LANDSCAPE_GROUP_BY_TACTIC,
  type LandscapeBucketData,
  type LandscapeDiffData,
  landscapeGroupBuckets,
  landscapeGroupTitle,
  type LandscapeItemData,
} from './timeMachineUtils';

const bucketsToEntries = (buckets: ReadonlyArray<LandscapeBucketData>, type?: string) => buckets.map((bucket) => ({
  label: bucket.label,
  value: bucket.count,
  id: type ? bucket.key : undefined,
  type,
}));

const itemsToEntries = (items: ReadonlyArray<LandscapeItemData>) => items.map((item) => ({
  label: item.name,
  value: item.count,
  id: item.id,
  type: item.entity_type,
}));

interface DistributionCardProps {
  title: string;
  entries: Array<{ label: string; value: number; id?: string; type?: string }>;
  testId: string;
  // Total number of items when the entries only keep the most frequent ones
  total?: number;
}

const DistributionCard = ({ title, entries, testId, total }: DistributionCardProps) => {
  const { t_i18n, n } = useFormatter();
  return (
    <Box data-testid={testId} sx={{ height: '100%' }}>
      <Card title={title}>
        {entries.length === 0 ? (
          <Text variant="content-compact" style={{ color: 'var(--text-default-secondary)' }}>{t_i18n('No change during this period.')}</Text>
        ) : (
          <>
            <Box sx={{ maxHeight: 320, overflow: 'auto' }}>
              <WidgetDistributionList data={entries} />
            </Box>
            {total !== undefined && total > entries.length && (
              <Text variant="content-caption" as="p" style={{ color: 'var(--text-default-secondary)', marginTop: 8 }} data-testid={`${testId}-total`}>
                {t_i18n('{shown} most frequent of {total}', { values: { shown: n(entries.length), total: n(total) } })}
              </Text>
            )}
          </>
        )}
      </Card>
    </Box>
  );
};

interface LandscapeChangesResultsProps {
  diff: LandscapeDiffData;
  truncated?: boolean;
  // Compare the same scope over a longer period, offered when nothing changed
  onWidenPeriod?: () => void;
}

/**
 * Aggregates and per-entity drill-down of a landscape diff.
 */
const LandscapeChangesResults = ({ diff, truncated = false, onWidenPeriod }: LandscapeChangesResultsProps) => {
  const { t_i18n, n } = useFormatter();
  const { aggregates } = diff;
  if (!aggregates) return null;
  const period = { from: diff.from, to: diff.to };
  const transition = (before?: number | null, after?: number | null) => {
    if ((before ?? null) === (after ?? null)) return <Text variant="content-caption" style={{ color: 'var(--text-default-secondary)' }}>{t_i18n('Unchanged')}</Text>;
    return t_i18n('{before} -> {after}', { values: { before: before ?? t_i18n('Not set'), after: after ?? t_i18n('Not set') } });
  };
  if (aggregates.entities_changed === 0 && aggregates.new_entities === 0) {
    return (
      <Alert
        severity="info"
        data-testid="landscape-changes-results"
        sx={{ alignItems: 'center' }}
        action={onWidenPeriod && <Button variant="secondary" onClick={onWidenPeriod}>{t_i18n('Widen the period')}</Button>}
      >
        {t_i18n('No change in this scope during this period')}
      </Alert>
    );
  }
  return (
    <Box data-testid="landscape-changes-results">
      {truncated && (
        <Alert severity="warning" sx={{ marginBottom: 2 }}>
          {t_i18n('The scope was too large, the landscape diff covers its most recent entities and relationships only.')}
        </Alert>
      )}
      <Grid container spacing={2} sx={{ marginBottom: 3 }}>
        <Grid size={{ xs: 6, md: 3, xl: 2 }}><TimeMachineSummaryCard label={t_i18n('Entities in scope')} value={n(aggregates.entities_in_scope)} /></Grid>
        <Grid size={{ xs: 6, md: 3, xl: 2 }}><TimeMachineSummaryCard label={t_i18n('Entities changed')} value={n(aggregates.entities_changed)} /></Grid>
        <Grid size={{ xs: 6, md: 3, xl: 2 }}><TimeMachineSummaryCard label={t_i18n('New entities')} value={n(aggregates.new_entities)} /></Grid>
        <Grid size={{ xs: 6, md: 3, xl: 2 }}><TimeMachineSummaryCard label={t_i18n('New relationships')} value={n(aggregates.new_relationships)} /></Grid>
        <Grid size={{ xs: 6, md: 3, xl: 2 }}><TimeMachineSummaryCard label={t_i18n('Removed relationships')} value={n(aggregates.removed_relationships)} /></Grid>
        <Grid size={{ xs: 6, md: 3, xl: 2 }}><TimeMachineSummaryCard label={t_i18n('Revocations')} value={n(aggregates.revocations)} /></Grid>
        <Grid size={{ xs: 6, md: 3, xl: 2 }}><TimeMachineSummaryCard label={t_i18n('Confidence changes')} value={n(aggregates.confidence_changes)} /></Grid>
        <Grid size={{ xs: 6, md: 3, xl: 2 }}><TimeMachineSummaryCard label={t_i18n('Score changes')} value={n(aggregates.score_changes)} /></Grid>
        <Grid size={{ xs: 6, md: 3, xl: 2 }}><TimeMachineSummaryCard label={t_i18n('New infrastructure')} value={n(aggregates.new_infrastructure_count)} /></Grid>
        <Grid size={{ xs: 6, md: 3, xl: 2 }}><TimeMachineSummaryCard label={t_i18n('New indicators')} value={n(aggregates.new_indicators_count)} /></Grid>
      </Grid>
      <Grid container spacing={3} sx={{ marginBottom: 3 }}>
        {/* The breakdown chosen with "Group by" comes first, the others follow without repeating it */}
        <Grid size={{ xs: 12, md: 6, xl: 4 }}>
          <DistributionCard title={t_i18n(landscapeGroupTitle(diff.group_by))} entries={bucketsToEntries(landscapeGroupBuckets(diff, t_i18n))} testId="landscape-groups" />
        </Grid>
        {diff.group_by !== LANDSCAPE_GROUP_BY_TACTIC && (
          <Grid size={{ xs: 12, md: 6, xl: 4 }}>
            <DistributionCard title={t_i18n('New techniques by tactic')} entries={bucketsToEntries(aggregates.new_techniques_by_tactic)} testId="landscape-techniques-by-tactic" />
          </Grid>
        )}
        <Grid size={{ xs: 12, md: 6, xl: 4 }}>
          <DistributionCard title={t_i18n('New techniques')} entries={itemsToEntries(aggregates.new_techniques)} total={aggregates.new_techniques_count} testId="landscape-techniques" />
        </Grid>
        {diff.group_by !== LANDSCAPE_GROUP_BY_RELATIONSHIP_TYPE && (
          <Grid size={{ xs: 12, md: 6, xl: 4 }}>
            <DistributionCard title={t_i18n('New relationships by type')} entries={bucketsToEntries(aggregates.new_relationships_by_type).map((entry) => ({ ...entry, label: t_i18n(`relationship_${entry.label}`) }))} testId="landscape-relationships-by-type" />
          </Grid>
        )}
        <Grid size={{ xs: 12, md: 6, xl: 4 }}>
          <DistributionCard title={t_i18n('New malware')} entries={itemsToEntries(aggregates.new_malware)} total={aggregates.new_malware_count} testId="landscape-malware" />
        </Grid>
        <Grid size={{ xs: 12, md: 6, xl: 4 }}>
          <DistributionCard title={t_i18n('New tools')} entries={itemsToEntries(aggregates.new_tools)} total={aggregates.new_tools_count} testId="landscape-tools" />
        </Grid>
        <Grid size={{ xs: 12, md: 6, xl: 4 }}>
          <DistributionCard title={t_i18n('New infrastructure')} entries={itemsToEntries(aggregates.new_infrastructure)} total={aggregates.new_infrastructure_count} testId="landscape-infrastructure" />
        </Grid>
        <Grid size={{ xs: 12, md: 6, xl: 4 }}>
          <DistributionCard title={t_i18n('New victims by sector')} entries={bucketsToEntries(aggregates.new_victims_by_sector, 'Sector')} testId="landscape-victims-sector" />
        </Grid>
        <Grid size={{ xs: 12, md: 6, xl: 4 }}>
          <DistributionCard title={t_i18n('New victims by country')} entries={bucketsToEntries(aggregates.new_victims_by_country, 'Country')} testId="landscape-victims-country" />
        </Grid>
        <Grid size={{ xs: 12, md: 6, xl: 4 }}>
          <DistributionCard title={t_i18n('New victims by region')} entries={bucketsToEntries(aggregates.new_victims_by_region, 'Region')} testId="landscape-victims-region" />
        </Grid>
      </Grid>
      <Card title={t_i18n('Top changed entities')}>
        {diff.entities.length === 0 ? (
          <Text variant="content-compact" style={{ color: 'var(--text-default-secondary)' }}>{t_i18n('No change during this period.')}</Text>
        ) : (
          <Table size="small" aria-label={t_i18n('Top changed entities')} data-testid="landscape-entities">
            <TableHead>
              <TableRow>
                <TableCell>{t_i18n('Entity')}</TableCell>
                <TableCell>{t_i18n('Type')}</TableCell>
                <TableCell align="right">{t_i18n('Relationships added')}</TableCell>
                <TableCell align="right">{t_i18n('Relationships removed')}</TableCell>
                <TableCell align="right">{t_i18n('Relationships revoked')}</TableCell>
                <TableCell align="right">{t_i18n('Confidence changes on relationships')}</TableCell>
                <TableCell align="right">{t_i18n('Attributes changed')}</TableCell>
                <TableCell>{t_i18n('Confidence')}</TableCell>
                <TableCell>{t_i18n('Score')}</TableCell>
                <TableCell align="right">{t_i18n('Change score')}</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {diff.entities.map((entity) => {
                const base = resolveLink(entity.entity_type);
                return (
                  <TableRow key={entity.entity_id}>
                    <TableCell>
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, flexWrap: 'wrap' }}>
                        {base ? <Link to={entityChangesPath(base, entity.entity_id, entity.entity_type, period)}>{entity.name}</Link> : entity.name}
                        {entity.created_in_period && <Chip label={t_i18n('New')} severity="info" />}
                        {entity.revoked_in_period && <Chip label={t_i18n('Revoked')} severity="medium" />}
                      </Box>
                    </TableCell>
                    <TableCell>{t_i18n(`entity_${entity.entity_type}`)}</TableCell>
                    <TableCell align="right">{n(entity.relationships_added)}</TableCell>
                    <TableCell align="right">{n(entity.relationships_removed)}</TableCell>
                    <TableCell align="right">{n(entity.relationships_revoked)}</TableCell>
                    <TableCell align="right">{n(entity.relationships_confidence_changed)}</TableCell>
                    <TableCell align="right">{n(entity.attributes_changed)}</TableCell>
                    <TableCell>{transition(entity.confidence_before, entity.confidence_after)}</TableCell>
                    <TableCell>{transition(entity.score_before, entity.score_after)}</TableCell>
                    <TableCell align="right">{n(entity.change_score)}</TableCell>
                  </TableRow>
                );
              })}
            </TableBody>
          </Table>
        )}
      </Card>
    </Box>
  );
};

export default LandscapeChangesResults;
