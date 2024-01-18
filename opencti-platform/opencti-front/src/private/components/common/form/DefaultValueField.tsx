import { Field } from 'formik';
import Alert from '@mui/lab/Alert/Alert';
import KillChainPhasesField from '@components/common/form/KillChainPhasesField';
import CreatedByField from '@components/common/form/CreatedByField';
import ObjectAssigneeField from '@components/common/form/ObjectAssigneeField';
import ObjectParticipantField from '@components/common/form/ObjectParticipantField';
import AuthorizedMembersField from '@components/common/form/AuthorizedMembersField';
import OpenVocabField from '@components/common/form/OpenVocabField';
import React from 'react';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import { INPUT_AUTHORIZED_MEMBERS } from '../../../../utils/authorizedMembers';
import DateTimePickerField from '../../../../components/DateTimePickerField';
import TextField from '../../../../components/TextField';
import MarkdownField from '../../../../components/MarkdownField';
import RichTextField from '../../../../components/RichTextField';
import SwitchField from '../../../../components/SwitchField';
import { useFormatter } from '../../../../components/i18n';
import useVocabularyCategory from '../../../../utils/hooks/useVocabularyCategory';

interface DefaultValueFieldProps {
  name: string,
  attribute: {
    name: string
    type: string
    multiple: boolean | null
  },
  setFieldValue: (field: string, value: string) => void,
  entityType?: string
}

const DefaultValueField = ({
  attribute,
  setFieldValue,
  entityType,
  name,
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
        TextFieldProps={{
          label,
          variant: 'standard',
          fullWidth: true,
          style: { marginTop: 20 },
        }}
      />
    );
  }
  // Handle single boolean
  if (attribute.type === 'boolean') {
    return (
      <Field
        component={SwitchField}
        type="checkbox"
        name={name}
        label={label}
        containerstyle={fieldSpacingContainerStyle}
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
    />
  );
};

export default DefaultValueField;
