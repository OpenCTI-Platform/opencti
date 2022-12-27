import { graphql, useMutation } from 'react-relay';
import Typography from '@mui/material/Typography';
import React from 'react';
import Switch from '@mui/material/Switch';
import { PreloadedQuery } from 'react-relay/relay-hooks/EntryPointTypes';
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
  mutation EntitySettingsPatchMutation($ids: [ID]!, $input: [EditInput]!) {
    entitySettingsFieldPatch(ids: $ids, input: $input) {
      ...EntitySetting_entitySetting
    }
  }
`;

export const entitySettingPatch = graphql`
  mutation EntitySettingPatchMutation($id: ID!, $input: [EditInput]!) {
    entitySettingFieldPatch(id: $id, input: $input) {
      ...EntitySetting_entitySetting
    }
  }
`;

const EntitySetting = ({ queryRef }: { queryRef: PreloadedQuery<EntitySettingQuery> }) => {
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

  const [commit] = useMutation(entitySettingPatch);

  const handleSubmitField = (name: string, value: boolean) => {
    commit({
      variables: { id: entitySetting.id, input: { key: name, value: value.toString() } },
    });
  };

  return (
    <div>
      {entitySetting.platform_entity_files_ref !== null
        && <div>
          <Typography variant="h3" gutterBottom={true}>
            {t('Entity automatic reference from files')}
          </Typography>
          <Switch
            checked={entitySetting.platform_entity_files_ref}
            onChange={() => handleSubmitField('platform_entity_files_ref', !entitySetting.platform_entity_files_ref)}
          />
        </div>
      }
      {entitySetting.platform_hidden_type !== null
        && <div>
          <Typography variant="h3" gutterBottom={true}>
            {t('Hidden entity type')}
          </Typography>
          <Switch
            checked={entitySetting.platform_hidden_type}
            onChange={() => handleSubmitField('platform_hidden_type', !entitySetting.platform_hidden_type)}
          />
        </div>
      }
      {entitySetting.enforce_reference !== null
        && <div>
          <Typography variant="h3" gutterBottom={true}>
            {t('Enforce reference on entity type')}
          </Typography>
          <Switch
            checked={entitySetting.enforce_reference}
            onChange={() => handleSubmitField('enforce_reference', !entitySetting.enforce_reference)}
          />
        </div>
      }
    </div>
  );
};

export default EntitySetting;
