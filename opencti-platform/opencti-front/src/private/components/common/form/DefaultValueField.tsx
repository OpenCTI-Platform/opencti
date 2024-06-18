import { Field } from 'formik';
import Alert from '@mui/lab/Alert';
import KillChainPhasesField from '@components/common/form/KillChainPhasesField';
import CreatedByField from '@components/common/form/CreatedByField';
import ObjectAssigneeField from '@components/common/form/ObjectAssigneeField';
import ObjectParticipantField from '@components/common/form/ObjectParticipantField';
import AuthorizedMembersField from '@components/common/form/AuthorizedMembersField';
import OpenVocabField from '@components/common/form/OpenVocabField';
import React from 'react';
import ObservableTypesField from '@components/common/form/ObservableTypesField';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import { INPUT_AUTHORIZED_MEMBERS } from '../../../../utils/authorizedMembers';
import DateTimePickerField from '../../../../components/DateTimePickerField';
import TextField from '../../../../components/TextField';
import MarkdownField from '../../../../components/fields/MarkdownField';
import RichTextField from '../../../../components/fields/RichTextField';
import SwitchField from '../../../../components/fields/SwitchField';
import { useFormatter } from '../../../../components/i18n';
import useVocabularyCategory from '../../../../utils/hooks/useVocabularyCategory';
import ToggleButtonField from '../../../../components/fields/ToggleButtonField';

interface DefaultValueFieldProps {
  name: string,
  attribute: {
    name: string
    type: string
    multiple: boolean | null | undefined
  },
  setFieldValue: (field: string, value: string) => void,
  entityType?: string
  disabled?: boolean
}

const DefaultValueField = ({
  attribute,
  setFieldValue,
  entityType,
  name,
  disabled = false,
}: DefaultValueFieldProps) => {
  const { t_i18n } = useFormatter();
  const label = t_i18n('Default value');
  const { fieldToCategory } = useVocabularyCategory();
  const ovCategory = entityType ? fieldToCategory(entityType, attribute.name) : undefined;

  // Handle object marking specific case : activate or deactivate default values (handle in access)
  if (attribute.name === 'objectMarking') {
    return (
      <>
        <Field
          component={SwitchField}
          type="checkbox"
          name={name}
          label={t_i18n('Activate/Deactivate default values')}
          fullWidth={true}
          containerstyle={{ marginTop: 20 }}
          disabled={disabled}
        />
        <Alert
          severity="info"
          variant="outlined"
          style={{ margin: '20px 0 10px 0' }}
        >
          {t_i18n(
            'When enabling a default value for marking definitions, it will put the group default markings ot the user which created the entity if nothing is provided.',
          )}
        </Alert>
      </>
    );
  }
  if (attribute.name === 'killChainPhases') {
    return (
      <KillChainPhasesField
        name={name}
        style={fieldSpacingContainerStyle}
        disabled={disabled}
      />
    );
  }
  // Handle createdBy
  if (attribute.name === 'createdBy') {
    return (
      <CreatedByField
        label={label}
        name={name}
        style={fieldSpacingContainerStyle}
        setFieldValue={setFieldValue}
        disabled={disabled}
      />
    );
  }
  // Handle objectAssignee
  if (attribute.name === 'objectAssignee') {
    return (
      <ObjectAssigneeField
        label={label}
        name={name}
        style={fieldSpacingContainerStyle}
        disabled={disabled}
      />
    );
  }
  // Handle objectParticipant
  if (attribute.name === 'objectParticipant') {
    return (
      <ObjectParticipantField
        label={label}
        name={name}
        style={fieldSpacingContainerStyle}
        disabled={disabled}
      />
    );
  }
  // Handle authorized members
  if (attribute.name === INPUT_AUTHORIZED_MEMBERS) {
    return (
      <Field
        name={name}
        component={AuthorizedMembersField}
        style={fieldSpacingContainerStyle}
        showAllMembersLine
        showCreatorLine
        canDeactivate
        disabled={disabled}
      />
    );
  }
  if (attribute.name === 'x_opencti_main_observable_type') {
    return (
      <ObservableTypesField
        name={name}
        label={label}
        style={fieldSpacingContainerStyle}
        disabled={disabled}
      />
    );
  }
  // Handle multiple & single OV
  if (ovCategory) {
    return (
      <OpenVocabField
        label={label}
        type={ovCategory}
        name={name}
        multiple={attribute.multiple ?? false}
        containerStyle={fieldSpacingContainerStyle}
        disabled={disabled}
      />
    );
  }
  // Handle single numeric
  if (attribute.type === 'date') {
    return (
      <Field
        label={label}
        component={DateTimePickerField}
        name={name}
        textFieldProps={{
          textField: {
            label,
            variant: 'standard',
            fullWidth: true,
            style: { marginTop: 20 },
          },
        }}
        disabled={disabled}
      />
    );
  }
  // Handle single boolean
  if (attribute.type === 'boolean') {
    return (
      <Field
        component={ToggleButtonField}
        items={[{ value: true, content: t_i18n('true') }, { value: false, content: t_i18n('false') }]}
        name={name}
        label={label}
        containerstyle={fieldSpacingContainerStyle}
        disabled={disabled}
      />
    );
  }
  // Handle single numeric
  if (attribute.type === 'numeric') {
    return (
      <Field
        component={TextField}
        type="number"
        variant="standard"
        name={name}
        label={label}
        fullWidth={true}
        style={{ marginTop: 20 }}
        disabled={disabled}
      />
    );
  }
  // Handle single string - Markdown
  if (attribute.name === 'description') {
    return (
      <Field
        component={MarkdownField}
        name={name}
        label={label}
        fullWidth={true}
        multiline={true}
        rows="4"
        style={{ marginTop: 20 }}
        disabled={disabled}
      />
    );
  }
  // Handle single string - Richtext
  if (attribute.name === 'content') {
    return (
      <Field
        component={RichTextField}
        name={name}
        label={label}
        fullWidth={true}
        disabled={disabled}
        style={{
          ...fieldSpacingContainerStyle,
          minHeight: 200,
          height: 200,
        }}
      />
    );
  }
  return (
    <Field
      component={TextField}
      variant="standard"
      name={name}
      label={label}
      fullWidth={true}
      style={{ marginTop: 20 }}
      disabled={disabled}
    />
  );
};

export default DefaultValueField;
