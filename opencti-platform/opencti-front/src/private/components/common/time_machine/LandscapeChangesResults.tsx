import React from 'react';
import { Link } from 'react-router';
import { Chip, Text } from '@filigran/design-system';
import { Alert, Box, Table, TableBody, TableCell, TableHead, TableRow } from '@mui/material';
import Grid from '@mui/material/Grid2';
import Card from '@common/card/Card';
import WidgetDistributionList from '../../../../components/dashboard/WidgetDistributionList';
import { useFormatter } from '../../../../components/i18n';
import { resolveLink } from '../../../../utils/Entity';
import TimeMachineSummaryCard from './TimeMachineSummaryCard';
import { comparePeriodSearch, type LandscapeBucketData, type LandscapeDiffData, type LandscapeItemData } from './timeMachineUtils';

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

const DistributionCard = ({ title, entries, testId }: { title: string; entries: Array<{ label: string; value: number; id?: string; type?: string }>; testId: string }) => {
  const { t_i18n } = useFormatter();
  return (
    <Box data-testid={testId} sx={{ height: '100%' }}>
      <Card title={title}>
        {entries.length === 0 ? (
          <Text variant="content-compact" style={{ color: 'var(--text-default-secondary)' }}>{t_i18n('No change during this period.')}</Text>
        ) : (
          <Box sx={{ maxHeight: 320, overflow: 'auto' }}>
            <WidgetDistributionList data={entries} />
          </Box>
        )}
      </Card>
    </Box>
  );
};

const delta = (before?: number | null, after?: number | null) => {
  if (before === null || before === undefined || after === null || after === undefined || before === after) return '-';
  return `${before} -> ${after}`;
};

interface LandscapeChangesResultsProps {
  diff: LandscapeDiffData;
  truncated?: boolean;
}

/**
 * Aggregates and per-entity drill-down of a landscape diff.
 */
const LandscapeChangesResults = ({ diff, truncated = false }: LandscapeChangesResultsProps) => {
  const { t_i18n, n } = useFormatter();
  const { aggregates } = diff;
  if (!aggregates) return null;
  const changesParams = comparePeriodSearch({ from: diff.from, to: diff.to });
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
        <Grid size={{ xs: 12, md: 6, xl: 4 }}>
          <DistributionCard title={t_i18n('New techniques by tactic')} entries={bucketsToEntries(aggregates.new_techniques_by_tactic)} testId="landscape-techniques-by-tactic" />
        </Grid>
        <Grid size={{ xs: 12, md: 6, xl: 4 }}>
          <DistributionCard title={t_i18n('New techniques')} entries={itemsToEntries(aggregates.new_techniques)} testId="landscape-techniques" />
        </Grid>
        <Grid size={{ xs: 12, md: 6, xl: 4 }}>
          <DistributionCard title={t_i18n('New relationships by type')} entries={bucketsToEntries(aggregates.new_relationships_by_type).map((entry) => ({ ...entry, label: t_i18n(`relationship_${entry.label}`) }))} testId="landscape-relationships-by-type" />
        </Grid>
        <Grid size={{ xs: 12, md: 6, xl: 4 }}>
          <DistributionCard title={t_i18n('New malware')} entries={itemsToEntries(aggregates.new_malware)} testId="landscape-malware" />
        </Grid>
        <Grid size={{ xs: 12, md: 6, xl: 4 }}>
          <DistributionCard title={t_i18n('New tools')} entries={itemsToEntries(aggregates.new_tools)} testId="landscape-tools" />
        </Grid>
        <Grid size={{ xs: 12, md: 6, xl: 4 }}>
          <DistributionCard title={t_i18n('New infrastructure')} entries={itemsToEntries(aggregates.new_infrastructure)} testId="landscape-infrastructure" />
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
                        {base ? <Link to={`${base}/${entity.entity_id}/changes?${changesParams}`}>{entity.name}</Link> : entity.name}
                        {entity.created_in_period && <Chip label={t_i18n('New')} severity="info" />}
                        {entity.revoked_in_period && <Chip label={t_i18n('Revoked')} severity="medium" />}
                      </Box>
                    </TableCell>
                    <TableCell>{t_i18n(`entity_${entity.entity_type}`)}</TableCell>
                    <TableCell align="right">{n(entity.relationships_added)}</TableCell>
                    <TableCell align="right">{n(entity.relationships_removed)}</TableCell>
                    <TableCell align="right">{n(entity.relationships_revoked)}</TableCell>
                    <TableCell align="right">{n(entity.attributes_changed)}</TableCell>
                    <TableCell>{delta(entity.confidence_before, entity.confidence_after)}</TableCell>
                    <TableCell>{delta(entity.score_before, entity.score_after)}</TableCell>
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
