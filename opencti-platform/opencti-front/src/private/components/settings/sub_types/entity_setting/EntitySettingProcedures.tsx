import React from 'react';
import Stack from '@mui/material/Stack';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue, Switch, Text } from '@filigran/design-system';
import { useFormatter } from '../../../../../components/i18n';
import { EntitySettingsFragment_entitySetting$data } from './__generated__/EntitySettingsFragment_entitySetting.graphql';
import { PROVENANCE_DOCUMENTATION } from './ProvenanceTrackingRow';

const PROCEDURES_DOCUMENTATION = `${PROVENANCE_DOCUMENTATION}#procedures`;

interface EntitySettingProceduresProps {
  entitySetting: EntitySettingsFragment_entitySetting$data;
  handleSubmitField: (name: string, value: boolean | string) => void;
}

/**
 * Procedures preserved on uses relationships to attack patterns (#15198), recorded with the provenance of relationships.
 */
const EntitySettingProcedures = ({ entitySetting, handleSubmitField }: EntitySettingProceduresProps) => {
  const { t_i18n } = useFormatter();
  const isTracked = !entitySetting.provenance_untracked_types.includes('uses');
  return (
    <Stack gap={2} data-testid="entity-setting-procedures">
      <Switch
        checked={entitySetting.procedures_preservation}
        disabled={!isTracked}
        label={t_i18n("Preserve each source's procedure")}
        onCheckedChange={(checked: boolean) => handleSubmitField('procedures_preservation', checked)}
      />
      <Text variant="content-caption" as="div">
        {isTracked
          ? t_i18n('On uses relationships to attack patterns.')
          : t_i18n('Needs uses relationships to be tracked.')}
        {' '}
        <Text variant="content-compact-link" as="a" href={PROCEDURES_DOCUMENTATION} target="_blank" rel="noreferrer">
          {t_i18n('Learn more')}
        </Text>
      </Text>
      <Stack gap={0.5} sx={{ maxWidth: 420 }}>
        <Text variant="content-base" as="div">{t_i18n('Description of the relationship')}</Text>
        <Select
          value={entitySetting.procedures_description_policy}
          disabled={!isTracked || !entitySetting.procedures_preservation}
          onValueChange={(value: string) => handleSubmitField('procedures_description_policy', value)}
        >
          <SelectTrigger aria-label={t_i18n('Description of the relationship')}>
            <SelectValue />
          </SelectTrigger>
          <SelectContent aria-label={t_i18n('Description of the relationship')}>
            <SelectItem value="longest">{t_i18n('Longest procedure')}</SelectItem>
            <SelectItem value="most_recent">{t_i18n('Most recent procedure')}</SelectItem>
          </SelectContent>
        </Select>
      </Stack>
    </Stack>
  );
};

export default EntitySettingProcedures;
