import Grid from '@mui/material/Grid';
import { graphql, useFragment } from 'react-relay';
import Card from '@common/card/Card';
import ErrorNotFound from '../../../../../components/ErrorNotFound';
import useApiMutation from '../../../../../utils/hooks/useApiMutation';
import { EntitySettingsFragment_entitySetting$key } from './__generated__/EntitySettingsFragment_entitySetting.graphql';
import { EntitySettingProvenanceRelationships_entitySetting$key } from './__generated__/EntitySettingProvenanceRelationships_entitySetting.graphql';
import EntitySettingReferences from './EntitySettingReferences';
import EntitySettingProvenance from './EntitySettingProvenance';
import EntitySettingProvenanceRelationships from './EntitySettingProvenanceRelationships';
import EntitySettingProcedures from './EntitySettingProcedures';
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
  provenanceRelationshipsData: EntitySettingProvenanceRelationships_entitySetting$key;
}

const EntitySettingSettings = ({ entitySettingsData, provenanceRelationshipsData }: EntitySettingSettingsProps) => {
  const { t_i18n } = useFormatter();

  const entitySetting = useFragment(entitySettingsFragment, entitySettingsData);
  if (!entitySetting) {
    return <ErrorNotFound />;
  }

  const [commit] = useApiMutation(entitySettingPatch);

  const handleSubmitField = (name: string, value: boolean | string) => {
    commit({
      variables: {
        ids: [entitySetting.id],
        input: { key: name, value: value.toString() },
      },
    });
  };
  // Relationships are tracked per relationship type: the list takes the width the procedures leave
  const isTrackedPerRelationshipType = entitySetting.availableSettings.includes('provenance_relationship_types');
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
      {isTrackedPerRelationshipType && (
        <Grid item xs={8}>
          <EntitySettingProvenanceRelationships entitySettingData={provenanceRelationshipsData} />
        </Grid>
      )}
      {!isTrackedPerRelationshipType && entitySetting.availableSettings.includes('provenance_tracking') && (
        <Grid item xs={6}>
          <Card title={t_i18n('Provenance')}>
            <EntitySettingProvenance
              entitySetting={entitySetting}
              handleSubmitField={handleSubmitField}
            />
          </Card>
        </Grid>
      )}
      {entitySetting.availableSettings.includes('procedures_preservation') && (
        <Grid item xs={isTrackedPerRelationshipType ? 4 : 6}>
          <Card title={t_i18n('Procedures')}>
            <EntitySettingProcedures
              entitySetting={entitySetting}
              handleSubmitField={handleSubmitField}
            />
          </Card>
        </Grid>
      )}
    </Grid>
  );
};

export default EntitySettingSettings;
