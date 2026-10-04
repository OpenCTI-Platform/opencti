import React from 'react';
import Stack from '@mui/material/Stack';
import { Switch, Text } from '@filigran/design-system';
import { useFormatter } from '../../../../../components/i18n';
import { EntitySettingsFragment_entitySetting$data } from './__generated__/EntitySettingsFragment_entitySetting.graphql';

interface EntitySettingProvenanceProps {
  entitySetting: EntitySettingsFragment_entitySetting$data;
  handleSubmitField: (name: string, value: boolean) => void;
}

/**
 * Provenance tracking of an entity type: sources, corroboration, conflicts and freshness of its elements.
 */
const EntitySettingProvenance = ({ entitySetting, handleSubmitField }: EntitySettingProvenanceProps) => {
  const { t_i18n } = useFormatter();
  return (
    <Stack gap={1} data-testid="entity-setting-provenance">
      <Switch
        checked={entitySetting.provenance_tracking}
        label={t_i18n('Track sources and corroboration')}
        onCheckedChange={(checked: boolean) => handleSubmitField('provenance_tracking', checked)}
      />
      <Text variant="content-caption" as="div">
        {t_i18n('Records the sources asserting each element of this type, their corroboration, conflicting values and freshness, shown in the Sources widget of the overview. Each new assertion costs a write: enable it on the types you curate.')}
      </Text>
    </Stack>
  );
};

export default EntitySettingProvenance;
