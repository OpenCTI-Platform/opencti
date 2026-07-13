import Button from '@common/button/Button';
import { CaseIncidentsLinesCasesPaginationQuery$variables } from '@components/cases/__generated__/CaseIncidentsLinesCasesPaginationQuery.graphql';
import Drawer, { DrawerControlledDialProps } from '@components/common/drawer/Drawer';
import AuthorizedMembersField from '@components/common/form/AuthorizedMembersField';
import AccordionDetails from '@mui/material/AccordionDetails';
import Typography from '@mui/material/Typography';
import Divider from '@mui/material/Divider';
import FormControlLabel from '@mui/material/FormControlLabel';
import MenuItem from '@mui/material/MenuItem';
import MuiAutocomplete from '@mui/material/Autocomplete';
import Chip from '@mui/material/Chip';
import MuiTextField from '@mui/material/TextField';
import Switch from '@mui/material/Switch';
import { Field, Form, Formik } from 'formik';
import { FormikConfig } from 'formik/dist/types';
import { FunctionComponent, useState } from 'react';
import { graphql, useLazyLoadQuery } from 'react-relay';
import { useNavigate } from 'react-router-dom';
import { RecordSourceSelectorProxy } from 'relay-runtime';
import { handleErrorInForm } from 'src/relay/environment';
import * as Yup from 'yup';
import { Accordion, AccordionSummary } from '../../../../components/Accordion';
import FormButtonContainer from '../../../../components/common/form/FormButtonContainer';
import CreateEntityControlledDial from '../../../../components/CreateEntityControlledDial';
import DateTimePickerField from '../../../../components/DateTimePickerField';
import DatePicker from '../../../../components/common/input/DatePicker';
import MarkdownField from '../../../../components/fields/markdownField/MarkdownField';
import RichTextField from '../../../../components/fields/RichTextField';
import { useFormatter } from '../../../../components/i18n';
import TextField from '../../../../components/TextField';
import { FieldOption, fieldSpacingContainerStyle } from '../../../../utils/field';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import useDefaultValues from '../../../../utils/hooks/useDefaultValues';
import useEnterpriseEdition from '../../../../utils/hooks/useEnterpriseEdition';
import { useDynamicSchemaCreationValidation, useIsMandatoryAttribute, yupShapeConditionalRequired } from '../../../../utils/hooks/useEntitySettings';
import useGranted, { KNOWLEDGE_KNUPDATE_KNMANAGEAUTHMEMBERS } from '../../../../utils/hooks/useGranted';
import useMarkdownCreationFilesInput from '../../../../utils/markdown/useMarkdownCreationFilesInput';
import Security from '../../../../utils/Security';
import { insertNode } from '../../../../utils/store';
import CustomFileUploader from '../../common/files/CustomFileUploader';
import CaseTemplateField from '../../common/form/CaseTemplateField';
import ConfidenceField from '../../common/form/ConfidenceField';
import CreatedByField from '../../common/form/CreatedByField';
import { ExternalReferencesField } from '../../common/form/ExternalReferencesField';
import ObjectAssigneeField from '../../common/form/ObjectAssigneeField';
import ObjectLabelField from '../../common/form/ObjectLabelField';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';
import ObjectParticipantField from '../../common/form/ObjectParticipantField';
import OpenVocabField from '../../common/form/OpenVocabField';
import { CaseIncidentAddInput, CaseIncidentCreationCaseMutation } from './__generated__/CaseIncidentCreationCaseMutation.graphql';
import {
  CaseIncidentCreationCustomFieldDefinitionsQuery,
  CaseIncidentCreationCustomFieldDefinitionsQuery$data,
} from './__generated__/CaseIncidentCreationCustomFieldDefinitionsQuery.graphql';

const customFieldDefinitionsForEntityTypeQuery = graphql`
  query CaseIncidentCreationCustomFieldDefinitionsQuery($entityType: String!) {
    customFieldDefinitionsForEntityType(entityType: $entityType) {
      edges {
        node {
          id
          name
          label
          field_type
          min_value
          max_value
          select_options
          entity_type_settings {
            entity_type
            mandatory
            default_value
          }
        }
      }
    }
  }
`;

type CustomFieldDef = NonNullable<NonNullable<CaseIncidentCreationCustomFieldDefinitionsQuery$data['customFieldDefinitionsForEntityType']>['edges']>[number]['node'];

const getCustomFieldSetting = (definition: CustomFieldDef, entityType: string) => (definition.entity_type_settings ?? []).find((setting) => setting.entity_type === entityType);

// Renders the appropriate Formik-less input for a custom field definition; value/onChange are wired to Formik state by the caller.
const CaseIncidentCustomFieldInput: FunctionComponent<{
  definition: CustomFieldDef;
  mandatory: boolean;
  value: string | boolean | string[];
  onChange: (val: string | boolean | string[]) => void;
}> = ({ definition, mandatory, value, onChange }) => {
  const { t_i18n } = useFormatter();
  const label = `${definition.label}${mandatory ? ' *' : ''}`;

  if (definition.field_type === 'boolean') {
    return (
      <FormControlLabel
        style={fieldSpacingContainerStyle}
        control={(
          <Switch
            checked={value === true}
            onChange={(_, checked) => onChange(checked)}
          />
        )}
        label={label}
      />
    );
  }
  if (definition.field_type === 'date') {
    return (
      <DatePicker
        value={value ? new Date(String(value)) : null}
        onChange={(date) => onChange(date ? date.toISOString() : '')}
        label={label}
        slotProps={{ textField: { variant: 'standard', fullWidth: true, style: fieldSpacingContainerStyle } }}
      />
    );
  }
  if (definition.field_type === 'select' && definition.select_options) {
    return (
      <MuiTextField
        select
        fullWidth
        variant="standard"
        label={label}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        style={fieldSpacingContainerStyle}
      >
        <MenuItem value=""><em>{t_i18n('None')}</em></MenuItem>
        {definition.select_options.map((opt) => (
          <MenuItem key={opt} value={opt}>{opt}</MenuItem>
        ))}
      </MuiTextField>
    );
  }
  if (definition.field_type === 'multi_select' && definition.select_options) {
    const selected = Array.isArray(value) ? value : [];
    return (
      <MuiAutocomplete
        multiple
        options={definition.select_options}
        value={selected}
        onChange={(_, newValue) => onChange(newValue)}
        renderTags={(tagValue, getTagProps) => tagValue.map((option: string, index: number) => (
          <Chip label={option} {...getTagProps({ index })} key={option} />
        ))}
        renderInput={(params) => (
          <MuiTextField
            {...params}
            variant="standard"
            label={label}
            style={fieldSpacingContainerStyle}
          />
        )}
      />
    );
  }
  if (definition.field_type === 'markdown') {
    return (
      <Field
        component={MarkdownField}
        name={`customFields.${definition.id}`}
        label={label}
        required={mandatory}
        fullWidth
        multiline
        rows="4"
        style={fieldSpacingContainerStyle}
      />
    );
  }
  return (
    <MuiTextField
      fullWidth
      variant="standard"
      label={label}
      value={value}
      type={definition.field_type === 'integer' ? 'number' : 'text'}
      inputProps={
        definition.field_type === 'integer'
          ? { min: definition.min_value ?? undefined, max: definition.max_value ?? undefined }
          : undefined
      }
      onChange={(e) => onChange(e.target.value)}
      style={fieldSpacingContainerStyle}
    />
  );
};

const caseIncidentMutation = graphql`
  mutation CaseIncidentCreationCaseMutation($input: CaseIncidentAddInput!) {
    caseIncidentAdd(input: $input) {
      id
      standard_id
      entity_type
      parent_types
      name
      representative {
        main
      }
      description
      response_types
      ...CaseIncidentsLineCase_node
    }
  }
`;

interface FormikCaseIncidentAddInput {
  name: string;
  confidence: number | undefined;
  severity: string;
  priority: string;
  description: string;
  content: string;
  file: File | undefined;
  createdBy: FieldOption | undefined;
  objectMarking: FieldOption[];
  objectAssignee: FieldOption[];
  objectParticipant: FieldOption[];
  objectLabel: FieldOption[];
  externalReferences: FieldOption[];
  created: Date | null;
  response_types: string[];
  caseTemplates?: FieldOption[];
  authorized_members: {
    value: string;
    accessRight: string;
    groupsRestriction: {
      label: string;
      value: string;
      type: string;
    }[]; }[] | undefined;
  // custom field values, keyed by definition id
  customFields: Record<string, string | boolean | string[]>;
}

interface IncidentFormProps {
  updater: (
    store: RecordSourceSelectorProxy,
    key: string,
    response: { id: string; name: string } | null | undefined,
  ) => void;
  onClose?: () => void;
  defaultConfidence?: number;
  defaultCreatedBy?: { value: string; label: string };
  defaultMarkingDefinitions?: { value: string; label: string }[];
  inputValue?: string;
}

const CASE_INCIDENT_TYPE = 'Case-Incident';

export const CaseIncidentCreationForm: FunctionComponent<IncidentFormProps> = ({
  updater,
  onClose,
  defaultConfidence,
  defaultCreatedBy,
  defaultMarkingDefinitions,
  inputValue,
}) => {
  const { t_i18n } = useFormatter();
  const navigate = useNavigate();
  const [mapAfter, setMapAfter] = useState<boolean>(false);
  const canEditAuthorizedMembers = useGranted([KNOWLEDGE_KNUPDATE_KNMANAGEAUTHMEMBERS]);
  const isEnterpriseEdition = useEnterpriseEdition();
  const { mandatoryAttributes } = useIsMandatoryAttribute(
    CASE_INCIDENT_TYPE,
  );
  const customFieldData = useLazyLoadQuery<CaseIncidentCreationCustomFieldDefinitionsQuery>(
    customFieldDefinitionsForEntityTypeQuery,
    { entityType: CASE_INCIDENT_TYPE },
  );
  const customFieldDefs: CustomFieldDef[] = (customFieldData.customFieldDefinitionsForEntityType?.edges ?? [])
    .map((edge) => edge.node);
  const basicShape = yupShapeConditionalRequired({
    name: Yup.string().trim().min(2),
    description: Yup.string().nullable(),
    content: Yup.string().nullable(),
    authorized_members: Yup.array().nullable(),
  }, mandatoryAttributes);
  const validator = useDynamicSchemaCreationValidation(
    mandatoryAttributes,
    basicShape,
  );
  const [commit] = useApiMutation<CaseIncidentCreationCaseMutation>(
    caseIncidentMutation,
    undefined,
    { successMessage: `${t_i18n('entity_Case-Incident')} ${t_i18n('successfully created')}` },
  );
  const { buildCreationFilesInput, registerMarkdownImagesController } = useMarkdownCreationFilesInput();
  const onSubmit: FormikConfig<FormikCaseIncidentAddInput>['onSubmit'] = (
    values,
    { setSubmitting, setErrors, resetForm },
  ) => {
    const customFieldValues = customFieldDefs
      .filter((def) => {
        const v = values.customFields[def.id];
        if (def.field_type === 'boolean') return true;
        if (Array.isArray(v)) return v.length > 0;
        return (v ?? '') !== '';
      })
      .map((def) => {
        const raw = values.customFields[def.id];
        const base = { field_id: def.id, field_name: def.name };
        switch (def.field_type) {
          case 'integer':
            return { ...base, int_value: parseInt(String(raw), 10) };
          case 'boolean':
            return { ...base, boolean_value: raw === true };
          case 'date':
            return { ...base, date_value: String(raw) };
          case 'select':
            return { ...base, select_value: String(raw) };
          case 'multi_select':
            return { ...base, select_values: Array.isArray(raw) ? raw : [] };
          default:
            return { ...base, string_value: String(raw) };
        }
      });
    const input: CaseIncidentAddInput = {
      ...buildCreationFilesInput(values.file ? [values.file] : []),
      name: values.name,
      description: values.description,
      content: values.content,
      created: values.created,
      severity: values.severity,
      priority: values.priority,
      response_types: values.response_types,
      caseTemplates: values.caseTemplates?.map(({ value }) => value),
      confidence: parseInt(String(values.confidence), 10),
      objectAssignee: values.objectAssignee.map(({ value }) => value),
      objectParticipant: values.objectParticipant.map(({ value }) => value),
      objectMarking: values.objectMarking.map(({ value }) => value),
      objectLabel: values.objectLabel.map(({ value }) => value),
      externalReferences: values.externalReferences.map(({ value }) => value),
      createdBy: values.createdBy?.value,
      customFieldValues: customFieldValues.length > 0 ? customFieldValues : undefined,
      ...(isEnterpriseEdition && canEditAuthorizedMembers && values.authorized_members && {
        authorized_members: values.authorized_members.map(({ value, accessRight, groupsRestriction }) => ({
          id: value,
          access_right: accessRight,
          groups_restriction_ids: groupsRestriction ? groupsRestriction.map((g) => g.value) : [],
        })),
      }),
    };
    commit({
      variables: {
        input,
      },
      updater: (store, response) => {
        if (updater && response) {
          updater(store, 'caseIncidentAdd', response.caseIncidentAdd);
        }
      },
      onError: (error) => {
        handleErrorInForm(error, setErrors);
        setSubmitting(false);
      },
      onCompleted: (response) => {
        setSubmitting(false);
        resetForm();
        if (onClose) {
          onClose();
        }
        if (mapAfter) {
          navigate(
            `/dashboard/cases/incidents/${response.caseIncidentAdd?.id}/content/mapping`,
          );
        }
      },
    });
  };

  const initialValues = useDefaultValues<FormikCaseIncidentAddInput>(
    CASE_INCIDENT_TYPE,
    {
      name: inputValue ?? '',
      confidence: defaultConfidence,
      description: '',
      content: '',
      severity: '',
      caseTemplates: [],
      response_types: [],
      created: null,
      priority: '',
      createdBy: defaultCreatedBy,
      objectMarking: defaultMarkingDefinitions ?? [],
      objectAssignee: [],
      objectParticipant: [],
      objectLabel: [],
      externalReferences: [],
      file: undefined,
      authorized_members: undefined,
      customFields: Object.fromEntries(
        customFieldDefs.map((def) => {
          const defaultValue = getCustomFieldSetting(def, CASE_INCIDENT_TYPE)?.default_value ?? null;
          if (def.field_type === 'boolean') {
            return [def.id, defaultValue === 'true'];
          }
          if (def.field_type === 'multi_select') {
            return [def.id, defaultValue ? [defaultValue] : []];
          }
          return [def.id, defaultValue ?? ''];
        }),
      ),
    },
  );
  if (!canEditAuthorizedMembers) {
    delete initialValues.authorized_members;
  }
  return (
    <Formik<FormikCaseIncidentAddInput>
      initialValues={initialValues}
      validationSchema={validator}
      onSubmit={onSubmit}
      validateOnChange={true}
      validateOnBlur={true}
      onReset={onClose}
    >
      {({ submitForm, handleReset, isSubmitting, setFieldValue, values, errors }) => (
        <Form>
          <Field
            component={TextField}
            variant="standard"
            name="name"
            label={t_i18n('Name')}
            required={(mandatoryAttributes.includes('name'))}
            fullWidth={true}
            detectDuplicate={['Case-Incident']}
            askAi={true}
          />
          <Field
            component={DateTimePickerField}
            name="created"
            textFieldProps={{
              label: t_i18n('Incident date'),
              required: mandatoryAttributes.includes('created'),
              variant: 'standard',
              fullWidth: true,
              style: { ...fieldSpacingContainerStyle },
            }}
          />
          <OpenVocabField
            label={t_i18n('Severity')}
            type="case_severity_ov"
            name="severity"
            required={(mandatoryAttributes.includes('severity'))}
            onChange={setFieldValue}
            containerStyle={fieldSpacingContainerStyle}
          />
          <OpenVocabField
            label={t_i18n('Priority')}
            type="case_priority_ov"
            name="priority"
            required={(mandatoryAttributes.includes('priority'))}
            onChange={setFieldValue}
            containerStyle={fieldSpacingContainerStyle}
          />
          <OpenVocabField
            label={t_i18n('Incident type')}
            type="incident_response_types_ov"
            name="response_types"
            required={(mandatoryAttributes.includes('response_types'))}
            multiple
            onChange={setFieldValue}
            containerStyle={fieldSpacingContainerStyle}
          />
          <CaseTemplateField
            onChange={setFieldValue}
            containerStyle={fieldSpacingContainerStyle}
          />
          <ConfidenceField
            entityType="Case-Incident"
            containerStyle={fieldSpacingContainerStyle}
          />
          <Field
            component={MarkdownField}
            name="description"
            label={t_i18n('Description')}
            required={(mandatoryAttributes.includes('priority'))}
            fullWidth={true}
            multiline={true}
            rows="4"
            style={fieldSpacingContainerStyle}
            askAi={true}
            autoPersistOnBlur={false}
            registerMarkdownImagesController={registerMarkdownImagesController}
            uploadFileMarkings={values.objectMarking.map(({ value }) => value)}
          />
          <Field
            component={RichTextField}
            name="content"
            label={t_i18n('Content')}
            required={(mandatoryAttributes.includes('content'))}
            meta={{ error: errors.content }}
            fullWidth={true}
            askAi={true}
            style={{
              ...fieldSpacingContainerStyle,
              minHeight: 200,
              height: 200,
            }}
          />
          <ObjectAssigneeField
            name="objectAssignee"
            required={(mandatoryAttributes.includes('objectAssignee'))}
            style={fieldSpacingContainerStyle}
          />
          <ObjectParticipantField
            name="objectParticipant"
            required={(mandatoryAttributes.includes('objectParticipant'))}
            style={fieldSpacingContainerStyle}
          />
          <CreatedByField
            name="createdBy"
            required={(mandatoryAttributes.includes('createdBy'))}
            style={fieldSpacingContainerStyle}
            setFieldValue={setFieldValue}
          />
          <ObjectLabelField
            name="objectLabel"
            required={(mandatoryAttributes.includes('objectLabel'))}
            style={fieldSpacingContainerStyle}
            setFieldValue={setFieldValue}
            values={values.objectLabel}
          />
          <ObjectMarkingField
            name="objectMarking"
            required={(mandatoryAttributes.includes('objectMarking'))}
            style={fieldSpacingContainerStyle}
            setFieldValue={setFieldValue}
          />
          <ExternalReferencesField
            name="externalReferences"
            required={(mandatoryAttributes.includes('externalReferences'))}
            style={fieldSpacingContainerStyle}
            setFieldValue={setFieldValue}
            values={values.externalReferences}
          />
          <CustomFileUploader setFieldValue={setFieldValue} />
          {customFieldDefs.length > 0 && (
            <>
              <Divider style={{ marginTop: 20 }} />
              {customFieldDefs.map((def) => (
                <CaseIncidentCustomFieldInput
                  key={def.id}
                  definition={def}
                  mandatory={getCustomFieldSetting(def, CASE_INCIDENT_TYPE)?.mandatory ?? false}
                  value={values.customFields[def.id]}
                  onChange={(val) => setFieldValue(`customFields.${def.id}`, val)}
                />
              ))}
            </>
          )}
          {isEnterpriseEdition && (
            <Security
              needs={[KNOWLEDGE_KNUPDATE_KNMANAGEAUTHMEMBERS]}
            >
              <div style={fieldSpacingContainerStyle}>
                <Accordion>
                  <AccordionSummary id="accordion-panel">
                    <Typography>{t_i18n('Advanced options')}</Typography>
                  </AccordionSummary>
                  <AccordionDetails>
                    <Field
                      name="authorized_members"
                      component={AuthorizedMembersField}
                      containerstyle={{ marginTop: 20 }}
                      showAllMembersLine
                      canDeactivate
                      disabled={isSubmitting}
                      addMeUserWithAdminRights
                    />
                  </AccordionDetails>
                </Accordion>
              </div>
            </Security>
          )}
          <FormButtonContainer>
            <Button
              variant="secondary"
              onClick={handleReset}
              disabled={isSubmitting}
            >
              {t_i18n('Cancel')}
            </Button>
            <Button
              onClick={submitForm}
              disabled={isSubmitting}
            >
              {t_i18n('Create')}
            </Button>
            {values.content.length > 0 && (
              <Button
                onClick={() => {
                  setMapAfter(true);
                  submitForm();
                }}
                disabled={isSubmitting}
              >
                {t_i18n('Create and map')}
              </Button>
            )}
          </FormButtonContainer>
        </Form>
      )}
    </Formik>
  );
};

const CaseIncidentCreation = ({
  paginationOptions,
}: {
  paginationOptions: CaseIncidentsLinesCasesPaginationQuery$variables;
}) => {
  const { t_i18n } = useFormatter();
  const updater = (store: RecordSourceSelectorProxy) => insertNode(
    store,
    'Pagination_incidents_caseIncidents',
    paginationOptions,
    'caseIncidentAdd',
  );
  const CreateCaseIncidentControlledDial = (props: DrawerControlledDialProps) => (
    <CreateEntityControlledDial entityType="Case-Incident" {...props} />
  );

  return (
    <Drawer
      title={t_i18n('Create an incident response')}
      controlledDial={CreateCaseIncidentControlledDial}
    >
      <CaseIncidentCreationForm updater={updater} />
    </Drawer>
  );
};

export default CaseIncidentCreation;
