import React from 'react';
import { graphql, useFragment } from 'react-relay';
import { CheckCircleOutlined, DoNotDisturbOnOutlined } from '@mui/icons-material';
import ListLines from '../../../../../components/list_lines/ListLines';
import ErrorNotFound from '../../../../../components/ErrorNotFound';
import { EntitySettingAttributeLine_attribute$data } from './__generated__/EntitySettingAttributeLine_attribute.graphql';
import { EntitySettingAttributes_entitySetting$key } from './__generated__/EntitySettingAttributes_entitySetting.graphql';
import EntitySettingAttributeLines, { AttributeNode } from './EntitySettingAttributeLines';
import { useFormatter } from '../../../../../components/i18n';
import { isNotEmptyField } from '../../../../../utils/utils';

const entitySettingAttributesFragment = graphql`
  fragment EntitySettingAttributes_entitySetting on EntitySetting {
    id
    target_type
    attributesDefinitions {
      name
      type
      label
      scale
      mandatory
      ...EntitySettingAttributeLine_attribute
    }
    attributes_configuration
  }
`;

interface EntitySettingAttributesProps {
  entitySettingsData: EntitySettingAttributes_entitySetting$key;
  searchTerm?: string;
}

const EntitySettingAttributes = ({
  entitySettingsData,
  searchTerm,
}: EntitySettingAttributesProps) => {
  const { t_i18n } = useFormatter();
  const entitySetting = useFragment(
    entitySettingAttributesFragment,
    entitySettingsData,
  );
  if (!entitySetting) {
    return <ErrorNotFound />;
  }

  const attributesMandatory = entitySetting.attributesDefinitions
    .filter((attr: { mandatory: boolean; name: string }) => attr.mandatory)
    .map((attr: { mandatory: boolean; name: string }) => attr.name);

  const dataColumns = {
    name: {
      label: 'Name',
      width: '50%',
      isSortable: false,
      render: (data: EntitySettingAttributeLine_attribute$data) => {
        const text = data.label ?? data.name;
        return t_i18n(text.charAt(0).toUpperCase() + text.slice(1));
      },
    },
    mandatory: {
      label: 'Mandatory',
      width: '25%',
      isSortable: false,
      render: (data: EntitySettingAttributeLine_attribute$data) => (
        <>
          {attributesMandatory.includes(data.name) ? (
            <CheckCircleOutlined
              fontSize="small"
              color={
                data.mandatoryType === 'customizable' ? 'success' : 'disabled'
              }
            />
          ) : (
            <DoNotDisturbOnOutlined
              fontSize="small"
              color={
                data.mandatoryType === 'customizable' ? 'primary' : 'disabled'
              }
            />
          )}
        </>
      ),
    },
    default_value: {
      label: 'Default value(s)',
      width: '25%',
      isSortable: false,
      render: (data: EntitySettingAttributeLine_attribute$data) => {
        return isNotEmptyField(data.defaultValues) ? (
          <CheckCircleOutlined
            fontSize="small"
            color={data.editDefault ? 'success' : 'disabled'}
          />
        ) : (
          <DoNotDisturbOnOutlined
            fontSize="small"
            color={data.editDefault ? 'primary' : 'disabled'}
          />
        );
      },
    },
  };
  const datas: { node: AttributeNode }[] = entitySetting.attributesDefinitions.map(
    (attr: AttributeNode) => ({ node: attr }),
  );
  return (
    <ListLines dataColumns={dataColumns} noFilters={true}>
      <EntitySettingAttributeLines
        datas={datas}
        dataColumns={dataColumns}
        keyword={searchTerm}
        entitySetting={entitySetting}
      />
    </ListLines>
  );
};

export default EntitySettingAttributes;
