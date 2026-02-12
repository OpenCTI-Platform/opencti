import React from 'react';
import { graphql, useFragment } from 'react-relay';
import Drawer from '@components/common/drawer/Drawer';
import { useFormatter } from '../../../../components/i18n';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import SSODefinitionForm, { SSODefinitionFormValues, SSOEditionFormInputKeys } from '@components/settings/sso_definitions/SSODefinitionForm';
import { SSODefinitionEditionMutation, SSODefinitionEditionMutation$variables } from '@components/settings/sso_definitions/__generated__/SSODefinitionEditionMutation.graphql';
import { SSODefinitionEditionFragment$key } from '@components/settings/sso_definitions/__generated__/SSODefinitionEditionFragment.graphql';
import { getConfigFromData, getSSOConfigList } from '@components/settings/sso_definitions/utils/getConfigAndAdvancedConfigFromData';
import { getStrategyConfigSelected } from '@components/settings/sso_definitions/utils/useStrategicConfig';
import { ConfigurationType, formatStringToArray } from '@components/settings/sso_definitions/utils/format';
import { SingleSignOnAddInput } from '@components/settings/sso_definitions/__generated__/SSODefinitionCreationMutation.graphql';
import { type EditInput } from './__generated__/SSODefinitionEditionMutation.graphql';

export const ssoDefinitionEditionMutation = graphql`
  mutation SSODefinitionEditionMutation($id: ID!, $input: [EditInput!]!) {
    singleSignOnFieldPatch(id: $id, input: $input) {
      ...SSODefinitionEditionFragment
    }
  }
`;

export const ssoDefinitionEditionFragment = graphql`
  fragment SSODefinitionEditionFragment on SingleSignOn {
    id
    name
    identifier
    label
    description
    enabled
    strategy
    organizations_management {
        organizations_path
        organizations_mapping
        organizations_scope
        read_userinfo
        token_reference
    }
    groups_management {
        group_attribute
        group_attributes
        groups_attributes
        groups_path
        groups_scope
        groups_mapping
        read_userinfo
        token_reference
    }
    configuration {
        key
        value
        type
    }
  }
`;

interface SSODefinitionEditionProps {
  isOpen: boolean;
  onClose: () => void;
  selectedStrategy: string;
  data: SSODefinitionEditionFragment$key;
}

const SSODefinitionEdition = ({
  isOpen,
  onClose,
  data,
  selectedStrategy,
}: SSODefinitionEditionProps) => {
  const { t_i18n } = useFormatter();
  const sso = useFragment(ssoDefinitionEditionFragment, data);

  const [editMutation] = useApiMutation<SSODefinitionEditionMutation>(
    ssoDefinitionEditionMutation,
    undefined,
    { successMessage: `${t_i18n('entity_SSO')} ${t_i18n('successfully updated')}` },
  );

  // const getGroupOrOrganizationManagementEditInputValue = (field: SSOEditionFormInputKeys, value: unknown, arrayValueList: string[]) => {
  //   let fieldValue: string = field;
  //   let inputValue = value;
  //   if (field.includes('token_reference')) fieldValue = 'token_reference';
  //   if (field.includes('read_userinfo')) {
  //     fieldValue = 'read_userinfo';
  //     inputValue = value === 'true';
  //   }
  //   if (arrayValueList.includes(field) && !Array.isArray(value)) {
  //     return { [fieldValue]: [inputValue] };
  //   }
  //   return { [fieldValue]: inputValue };
  // };

  // const onEdit = (field: SSOEditionFormInputKeys, value: unknown) => {
  //   const configurationKeyList = getSSOConfigList(selectedStrategy ?? '');
  //   const groupManagementKeyList = ['group_attribute', 'groups_attributes', 'group_attributes', 'groups_path', 'groups_scope', 'groups_mapping', 'groups_token_reference', 'groups_read_userinfo'];
  //   const organizationsManagementKeyList = ['organizations_path', 'organizations_mapping', 'organizations_scope', 'organizations_token_reference', 'organizations_read_userinfo'];
  //
  //   const input: { key: string; value: unknown[] } = { key: field, value: [value] };
  //
  //   if (configurationKeyList.includes(field)) {
  //     input.key = 'configuration';
  //     const configurations = [...(sso.configuration ?? [])];
  //     const foundIndex = configurations.findIndex((item) => item.key === field);
  //     const newEntry = {
  //       key: field,
  //       value: Array.isArray(value) ? JSON.stringify(value) : String(value),
  //       type: Array.isArray(value) ? 'array' : typeof value,
  //     };
  //     if (foundIndex === -1) {
  //       configurations.push(newEntry);
  //     } else {
  //       configurations[foundIndex] = newEntry;
  //     }
  //
  //     input.value = [...configurations];
  //   }
  //
  //   if (field === 'advancedConfigurations') {
  //     input.key = 'configuration';
  //     const config = getConfigFromData(sso.configuration ?? [], selectedStrategy ?? '');
  //     input.value = Array.isArray(value) ? [...config, ...value] : [...config];
  //   }
  //
  //   if (groupManagementKeyList.includes(field)) {
  //     const attributesFields = ['group_attributes', 'groups_attributes'];
  //     const arrayValueList = ['groups_path', 'groups_mapping', ...attributesFields];
  //     input.key = 'groups_management';
  //
  //     const currentValue = attributesFields.includes(field)
  //       ? formatStringToArray(String(value))
  //       : value;
  //
  //     const inputValue = getGroupOrOrganizationManagementEditInputValue(field, currentValue, arrayValueList);
  //     input.value = [{
  //       ...sso.groups_management,
  //       ...inputValue,
  //     }];
  //   }
  //
  //   if (organizationsManagementKeyList.includes(field)) {
  //     const arrayValueList = ['organizations_path', 'organizations_mapping'];
  //     input.key = 'organizations_management';
  //
  //     const currentValue = field === 'organizations_path'
  //       ? formatStringToArray(String(value))
  //       : value;
  //
  //     const inputValue = getGroupOrOrganizationManagementEditInputValue(field, currentValue, arrayValueList);
  //     input.value = [{
  //       ...sso.organizations_management,
  //       ...inputValue,
  //     }];
  //   }
  //
  //   editMutation({
  //     variables: { id: sso.id, input: [input] },
  //   });
  // };

  type InputType = EditInput;
  const onUpdate = (
    finalValues: SSODefinitionFormValues,
    { setSubmitting, resetForm }: { setSubmitting: (flag: boolean) => void; resetForm: () => void },
  ) => {
    const configurationKeyList = getSSOConfigList(selectedStrategy ?? '');
    const groupsManagementKeyList = ['group_attribute', 'groups_attributes', 'group_attributes', 'groups_path', 'groups_scope', 'groups_mapping', 'groups_token_reference', 'groups_read_userinfo'];
    const orgasManagementKeyList = ['organizations_path', 'organizations_mapping', 'organizations_scope', 'organizations_token_reference', 'organizations_read_userinfo'];
    //

    // Object.entries(finalValues).map(([key, value]) => {
    //   // Configurations
    //   if (configurationKeyList.includes(key)) {
    //     const configIndex = input.findIndex((item) => item.key === 'configurations');
    //     if (configIndex === -1) {
    //       input.push({
    //         key: 'configurations',
    //         operation: 'replace',
    //         value: [{ [key]: value }],
    //       });
    //     } else {
    //       const configInput: InputType = input[configIndex];
    //       input[configIndex].value = [...configInput.value, { key, value: Array.isArray(value) ? JSON.stringify(value) : String(value), type: typeof value }];
    //     }
    //   } else if (groupsManagementKeyList.includes(key)) { // Groups
    //     const groupsIndex = input.findIndex((item) => item.key === 'groups_management');
    //     if (groupsIndex === -1) {
    //       input.push({
    //         key: 'groups_management',
    //         operation: 'replace',
    //         value: [{ [key]: value }] });
    //     } else {
    //       const groupqInput: InputType = input[groupsIndex];
    //       input[groupsIndex].value = [...groupqInput.value, value];
    //     }
    //   } else if (orgasManagementKeyList.includes(key)) { // Orgas
    //     const orgasIndex = input.findIndex((item) => item.key === 'organizations_management');
    //     if (orgasIndex === -1) {
    //       input.push({
    //         key: 'organizations_management',
    //         operation: 'replace',
    //         value: [{ [key]: value }],
    //       });
    //     } else {
    //       const orgasInput: InputType = input[orgasIndex];
    //       input[orgasIndex].value = [...orgasInput.value, value];
    //     }
    //   } else if (key === 'advancedConfigurations') {
    //     const configIndex = input.findIndex((item) => item.key === 'configurations');
    //     if (configIndex === -1) {
    //       input.push({
    //         key: 'configurations',
    //         operation: 'replace',
    //         value: [...value],
    //       });
    //     } else {
    //       const configInput: InputType = input[configIndex];
    //       input[configIndex].value = [...configInput.value, value];
    //     }
    //   } else {
    //     input.push({ key, value });
    //   }
    // });

    const input: InputType[] = [];
    Object.entries(finalValues).forEach(([key, value]) => {
      let inputContent: EditInput = { key, value };
      if (configurationKeyList.includes(key)) {
        inputContent = {
          ...inputContent,
          key: 'configuration',
          object_path: `configuration/${key}`,
          value: [{ key, value, type: Array.isArray(value) ? 'array' : typeof value }],
        };
      } else if (groupsManagementKeyList.includes(key)) {
        let inputKey = key;
        if (key.includes('token_reference')) inputKey = 'token_reference';
        if (key.includes('read_userinfo')) inputKey = 'read_userinfo';
        inputContent = {
          ...inputContent,
          key: inputKey,
          object_path: `groups_management/${inputKey}`,
          value: [value],
        };
      } else if (orgasManagementKeyList.includes(key)) {
        let inputKey = key;
        if (key.includes('token_reference')) inputKey = 'token_reference';
        if (key.includes('read_userinfo')) inputKey = 'read_userinfo';
        inputContent = {
          ...inputContent,
          key: inputKey,
          object_path: `organizations_management/${inputKey}`,
          value,
        };
      }

      input.push(inputContent);
    });

    // if (finalValues.advancedConfigurations)
    console.log('finalValues : ', finalValues);
    console.log('input : ', input);
    setSubmitting(false);
    editMutation({
      variables: { id: sso.id, input },
    });
  };

  const strategyConfigSelected = getStrategyConfigSelected(selectedStrategy);

  return (
    <Drawer
      title={t_i18n(`Update a ${strategyConfigSelected} Authentication`)}
      open={isOpen}
      onClose={onClose}
    >
      <SSODefinitionForm onCancel={onClose} onSubmitEdition={onUpdate} data={sso} selectedStrategy={strategyConfigSelected} isEditing />
    </Drawer>
  );
};

export default SSODefinitionEdition;
