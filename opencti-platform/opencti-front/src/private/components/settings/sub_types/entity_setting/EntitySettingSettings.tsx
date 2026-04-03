import Grid from '@mui/material/Grid';
import { graphql, useFragment } from 'react-relay';
import Card from '@common/card/Card';
import ErrorNotFound from '../../../../../components/ErrorNotFound';
import useApiMutation from '../../../../../utils/hooks/useApiMutation';
import { EntitySettingsFragment_entitySetting$key } from './__generated__/EntitySettingsFragment_entitySetting.graphql';
import EntitySettingReferences from './EntitySettingReferences';
import { entitySettingsFragment } from './EntitySettingsFragment';
import EntitySettingVisibility from './EntitySettingVisibility';
import { useFormatter } from '../../../../../components/i18n';

export const entitySettingPatch = graphql`
  mutation EntitySettingSettingsPatchMutation(
    $ids: [ID!]!
    $input: [EditInput!]!
  ) {
    entitySettingsFieldPatch(ids: $ids, input: $input) {
      ...EntitySettingsFragment_entitySetting
    }
  }
`;

interface EntitySettingSettingsProps {
  entitySettingsData: EntitySettingsFragment_entitySetting$key;
}

const EntitySettingSettings = ({ entitySettingsData }: EntitySettingSettingsProps) => {
  const { t_i18n } = useFormatter();

  const entitySetting = useFragment(entitySettingsFragment, entitySettingsData);
  if (!entitySetting) {
    return <ErrorNotFound />;
  }

  const [commit] = useApiMutation(entitySettingPatch);

  const handleSubmitField = (name: string, value: boolean) => {
    commit({
      variables: {
        ids: [entitySetting.id],
        input: { key: name, value: value.toString() },
      },
    });
  };
  return (
    <Grid container={true} spacing={2}>
      <Grid item xs={6}>
        <Card title={t_i18n('Visibility')}>
          <EntitySettingVisibility
            entitySetting={entitySetting}
            handleSubmitField={handleSubmitField}
          />
        </Card>
      </Grid>
      <Grid item xs={6}>
        <Card title={t_i18n('References')}>
          <EntitySettingReferences
            entitySetting={entitySetting}
            handleSubmitField={handleSubmitField}
          />
        </Card>
      </Grid>
    </Grid>
  );
};

export default EntitySettingSettings;
