import React, { Suspense } from 'react';
import { graphql, useLazyLoadQuery } from 'react-relay';
import Stack from '@mui/material/Stack';
import Typography from '@mui/material/Typography';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue, Switch } from '@filigran/design-system';
import Card from '@common/card/Card';
import { useFormatter } from '../../../../components/i18n';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { ProvenanceSettingsCardQuery } from './__generated__/ProvenanceSettingsCardQuery.graphql';
import { ProvenanceSettingsCardFieldPatchMutation } from './__generated__/ProvenanceSettingsCardFieldPatchMutation.graphql';

const provenanceSettingsCardQuery = graphql`
  query ProvenanceSettingsCardQuery {
    settings {
      id
      platform_procedures_preservation
      platform_procedures_description_policy
    }
  }
`;

const provenanceSettingsCardFieldPatchMutation = graphql`
  mutation ProvenanceSettingsCardFieldPatchMutation($id: ID!, $input: [EditInput]!) {
    settingsEdit(id: $id) {
      fieldPatch(input: $input) {
        id
        platform_procedures_preservation
        platform_procedures_description_policy
      }
    }
  }
`;

const ProvenanceSettingsContent = () => {
  const { t_i18n } = useFormatter();
  const data = useLazyLoadQuery<ProvenanceSettingsCardQuery>(provenanceSettingsCardQuery, {});
  const [commit, inFlight] = useApiMutation<ProvenanceSettingsCardFieldPatchMutation>(provenanceSettingsCardFieldPatchMutation);
  const { settings } = data;
  const patch = (key: string, value: string) => commit({ variables: { id: settings.id, input: [{ key, value: [value] }] } });
  return (
    <Stack gap={2} data-testid="provenance-settings">
      <Switch
        checked={settings.platform_procedures_preservation}
        disabled={inFlight}
        label={t_i18n('Preserve distinct procedures on uses relationships to attack patterns')}
        onCheckedChange={(checked: boolean) => patch('platform_procedures_preservation', String(checked))}
      />
      <Typography variant="caption">
        {t_i18n('Each source keeps its own procedure description instead of overwriting the others, the relationship identity is unchanged.')}
      </Typography>
      <Stack gap={0.5} sx={{ maxWidth: 420 }}>
        <Typography variant="body2">{t_i18n('Description of the relationship')}</Typography>
        <Select
          value={settings.platform_procedures_description_policy}
          disabled={inFlight || !settings.platform_procedures_preservation}
          onValueChange={(value: string) => patch('platform_procedures_description_policy', value)}
        >
          <SelectTrigger aria-label={t_i18n('Description of the relationship')}>
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="longest">{t_i18n('Longest procedure')}</SelectItem>
            <SelectItem value="most_recent">{t_i18n('Most recent procedure')}</SelectItem>
          </SelectContent>
        </Select>
      </Stack>
    </Stack>
  );
};

/**
 * Platform settings of the provenance tracking (procedures preservation, issue #15198).
 */
const ProvenanceSettingsCard = () => {
  const { t_i18n } = useFormatter();
  return (
    <Card title={t_i18n('Procedures')}>
      <Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
        <ProvenanceSettingsContent />
      </Suspense>
    </Card>
  );
};

export default ProvenanceSettingsCard;
