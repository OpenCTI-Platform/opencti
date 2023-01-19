import { graphql, useMutation } from 'react-relay';
import Typography from '@mui/material/Typography';
import React from 'react';
import Switch from '@mui/material/Switch';
import { PreloadedQuery } from 'react-relay/relay-hooks/EntryPointTypes';
import Grid from '@mui/material/Grid';
import { Tooltip } from '@mui/material';
import FormControlLabel from '@mui/material/FormControlLabel';
import FormGroup from '@mui/material/FormGroup';
import { useFormatter } from '../../../../components/i18n';
import usePreloadedFragment from '../../../../utils/hooks/usePreloadedFragment';
import { EntitySettingQuery } from './__generated__/EntitySettingQuery.graphql';
import { EntitySetting_entitySetting$key } from './__generated__/EntitySetting_entitySetting.graphql';

export const entitySettingsFragment = graphql`
  fragment EntitySettingConnection_entitySettings on EntitySettingConnection {
    edges {
      node {
        ...EntitySetting_entitySetting
      }
    }
  }
`;

export const entitySettingsQuery = graphql`
  query EntitySettingsQuery {
    entitySettings {
      ...EntitySettingConnection_entitySettings
    }
  }
`;

export const entitySettingFragment = graphql`
  fragment EntitySetting_entitySetting on EntitySetting {
    id
    enforce_reference
    platform_entity_files_ref
    platform_hidden_type
    target_type
  }
`;

export const entitySettingQuery = graphql`
  query EntitySettingQuery($targetType: String!) {
    entitySettingByType(targetType: $targetType) {
      ...EntitySetting_entitySetting
    }
  }
`;

export const entitySettingsPatch = graphql`
  mutation EntitySettingsPatchMutation($ids: [ID!]!, $input: [EditInput!]!) {
    entitySettingsFieldPatch(ids: $ids, input: $input) {
      ...EntitySetting_entitySetting
    }
  }
`;

const EntitySetting = ({
  queryRef,
}: {
  queryRef: PreloadedQuery<EntitySettingQuery>;
}) => {
  const { t } = useFormatter();

  const entitySetting = usePreloadedFragment<
  EntitySettingQuery,
  EntitySetting_entitySetting$key
  >({
    linesQuery: entitySettingQuery,
    linesFragment: entitySettingFragment,
    queryRef,
    nodePath: 'entitySettingByType',
  });

  const [commit] = useMutation(entitySettingsPatch);

  const handleSubmitField = (name: string, value: boolean) => {
    commit({
      variables: {
        ids: [entitySetting.id],
        input: { key: name, value: value.toString() },
      },
    });
  };

  return (
    <Grid container={true} spacing={3}>
      <Grid item={true} xs={6}>
        <div>
          <Tooltip
            title={
              entitySetting.platform_entity_files_ref === null
                ? t('This configuration is not available for this entity type')
                : t(
                  'This configuration enables an entity to automatically construct an external reference from the uploaded file.',
                )
            }
          >
            <Typography variant="h3" gutterBottom={true}>
              {t('Entity automatic reference from files')}
            </Typography>
          </Tooltip>
          <FormGroup>
            <FormControlLabel
              control={
                <Switch
                  disabled={entitySetting.platform_entity_files_ref === null}
                  checked={entitySetting.platform_entity_files_ref ?? false}
                  onChange={() => handleSubmitField(
                    'platform_entity_files_ref',
                    !entitySetting.platform_entity_files_ref,
                  )
                  }
                />
              }
              label={t('Enable this feature')}
            />
          </FormGroup>
        </div>
        <div style={{ marginTop: 20 }}>
          <Tooltip
            title={
              entitySetting.platform_hidden_type === null
                ? t('This configuration is not available for this entity type')
                : t(
                  'This configuration hidde a specific entity type across the entire platform.',
                )
            }
          >
            <Typography variant="h3" gutterBottom={true}>
              {t('Hidden entity type')}
            </Typography>
          </Tooltip>
          <FormGroup>
            <FormControlLabel
              control={
                <Switch
                  disabled={entitySetting.platform_hidden_type === null}
                  checked={entitySetting.platform_hidden_type ?? false}
                  onChange={() => handleSubmitField(
                    'platform_hidden_type',
                    !entitySetting.platform_hidden_type,
                  )
                  }
                />
              }
              label={t('Enable this feature')}
            />
          </FormGroup>
        </div>
      </Grid>
      <Grid item={true} xs={6}>
        <div>
          <Tooltip
            title={
              entitySetting.enforce_reference === null
                ? t('This configuration is not available for this entity type')
                : t(
                  'This configuration enables the requirement of a reference message on an entity update.',
                )
            }
          >
            <Typography variant="h3" gutterBottom={true}>
              {t('Enforce reference on entity type')}
            </Typography>
          </Tooltip>
          <FormGroup>
            <FormControlLabel
              control={
                <Switch
                  disabled={entitySetting.enforce_reference === null}
                  checked={entitySetting.enforce_reference ?? false}
                  onChange={() => handleSubmitField(
                    'enforce_reference',
                    !entitySetting.enforce_reference,
                  )
                  }
                />
              }
              label={t('Enable this feature')}
            />
          </FormGroup>
        </div>
      </Grid>
    </Grid>
  );
};

export default EntitySetting;
