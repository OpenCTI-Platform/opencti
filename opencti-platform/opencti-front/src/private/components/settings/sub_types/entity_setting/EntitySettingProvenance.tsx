import React, { Suspense } from 'react';
import { PreloadedQuery, usePreloadedQuery } from 'react-relay';
import Box from '@mui/material/Box';
import Stack from '@mui/material/Stack';
import { Text } from '@filigran/design-system';
import { useFormatter } from '../../../../../components/i18n';
import useQueryLoading from '../../../../../utils/hooks/useQueryLoading';
import { EntitySettingsFragment_entitySetting$data } from './__generated__/EntitySettingsFragment_entitySetting.graphql';
import { ProvenanceTrackingRowStatisticsQuery } from './__generated__/ProvenanceTrackingRowStatisticsQuery.graphql';
import ProvenanceTrackingRow, { PROVENANCE_DOCUMENTATION, provenanceTrackingRowStatisticsQuery, sumProvenanceStatistics } from './ProvenanceTrackingRow';

interface EntitySettingProvenanceProps {
  entitySetting: EntitySettingsFragment_entitySetting$data;
  handleSubmitField: (name: string, value: boolean) => void;
}

type TrackingRowProps = Omit<React.ComponentProps<typeof ProvenanceTrackingRow>, 'statistics'>;

const EntitySettingProvenanceStatistics = ({ queryRef, ...rowProps }: TrackingRowProps & { queryRef: PreloadedQuery<ProvenanceTrackingRowStatisticsQuery> }) => {
  const { provenanceTypeStatistics } = usePreloadedQuery(provenanceTrackingRowStatisticsQuery, queryRef);
  return <ProvenanceTrackingRow {...rowProps} statistics={sumProvenanceStatistics(provenanceTypeStatistics)} />;
};

/**
 * Provenance tracking of an entity type: sources, corroboration, conflicts and freshness of its elements.
 */
const EntitySettingProvenance = ({ entitySetting, handleSubmitField }: EntitySettingProvenanceProps) => {
  const { t_i18n } = useFormatter();
  const queryRef = useQueryLoading<ProvenanceTrackingRowStatisticsQuery>(provenanceTrackingRowStatisticsQuery, { types: [entitySetting.target_type] });
  const rowProps: TrackingRowProps = {
    label: t_i18n('Track sources and corroboration'),
    switchLabel: t_i18n('Track sources and corroboration'),
    tracked: entitySetting.provenance_tracking,
    onTrackedChange: (checked: boolean) => handleSubmitField('provenance_tracking', checked),
    standalone: true,
  };
  const loading = <ProvenanceTrackingRow {...rowProps} statistics={undefined} />;
  return (
    <Stack gap={1.5} data-testid="entity-setting-provenance">
      <Box role="table" aria-label={t_i18n('Provenance')}>
        <Suspense fallback={loading}>
          {queryRef ? <EntitySettingProvenanceStatistics {...rowProps} queryRef={queryRef} /> : loading}
        </Suspense>
      </Box>
      <Text variant="content-caption" as="p">
        {t_i18n('Records who asserts each element of this type, to measure its corroboration and freshness.')}
        {' '}
        <Text variant="content-compact-link" as="a" href={`${PROVENANCE_DOCUMENTATION}#entity-types-tracked`} target="_blank" rel="noreferrer">
          {t_i18n('Learn more')}
        </Text>
      </Text>
    </Stack>
  );
};

export default EntitySettingProvenance;
