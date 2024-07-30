import Button from '@mui/material/Button';
import Drawer, { DrawerControlledDialProps, DrawerVariant } from '@components/common/drawer/Drawer';
import makeStyles from '@mui/styles/makeStyles';
import { Field, Form, Formik } from 'formik';
import { FormikConfig } from 'formik/dist/types';
import React, { FunctionComponent, useState } from 'react';
import { graphql } from 'react-relay';
import { RecordSourceSelectorProxy } from 'relay-runtime';
import * as Yup from 'yup';
import { useNavigate } from 'react-router-dom';
import { handleErrorInForm } from 'src/relay/environment';
import { CaseRftsLinesCasesPaginationQuery$variables } from '@components/cases/__generated__/CaseRftsLinesCasesPaginationQuery.graphql';
import DateTimePickerField from '../../../../components/DateTimePickerField';
import { useFormatter } from '../../../../components/i18n';
import MarkdownField from '../../../../components/fields/MarkdownField';
import TextField from '../../../../components/TextField';
import type { Theme } from '../../../../components/Theme';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import { useSchemaCreationValidation } from '../../../../utils/hooks/useEntitySettings';
import { insertNode } from '../../../../utils/store';
import CaseTemplateField from '../../common/form/CaseTemplateField';
import ConfidenceField from '../../common/form/ConfidenceField';
import CreatedByField from '../../common/form/CreatedByField';
import { ExternalReferencesField } from '../../common/form/ExternalReferencesField';
import ObjectAssigneeField from '../../common/form/ObjectAssigneeField';
import ObjectLabelField from '../../common/form/ObjectLabelField';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';
import OpenVocabField from '../../common/form/OpenVocabField';
import { Option } from '../../common/form/ReferenceField';
import { CaseRftAddInput, CaseRftCreationCaseMutation } from './__generated__/CaseRftCreationCaseMutation.graphql';
import useDefaultValues from '../../../../utils/hooks/useDefaultValues';
import RichTextField from '../../../../components/fields/RichTextField';
import ObjectParticipantField from '../../common/form/ObjectParticipantField';
import CustomFileUploader from '../../common/files/CustomFileUploader';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import useHelper from '../../../../utils/hooks/useHelper';
import CreateEntityControlledDial from '../../../../components/CreateEntityControlledDial';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles<Theme>((theme) => ({
  buttons: {
    marginTop: 20,
    textAlign: 'right',
  },
  button: {
    marginLeft: theme.spacing(2),
  },
}));

const caseRftMutation = graphql`
  mutation CaseRftCreationCaseMutation($input: CaseRftAddInput!) {
    caseRftAdd(input: $input) {
      id
      standard_id
      entity_type
      parent_types
      name
      description
      ...CaseRftsLineCases_data
    }
  }
`;

interface FormikCaseRftAddInput {
  name: string;
  confidence: number | undefined;
  description: string;
  content: string;
  file: File | undefined;
  createdBy: Option | undefined;
  objectMarking: Option[];
  objectAssignee: Option[];
  objectParticipant: Option[];
  objectLabel: Option[];
  externalReferences: Option[];
  created: Date | null;
  takedown_types: string[];
  severity: string;
  priority: string;
  caseTemplates?: Option[];
}

interface CaseRftFormProps {
  updater: (
    store: RecordSourceSelectorProxy,
    key: string,
    response: { id: string; name: string } | null | undefined
  ) => void;
  onClose?: () => void;
  defaultConfidence?: number;
  defaultCreatedBy?: { value: string; label: string };
  defaultMarkingDefinitions?: { value: string; label: string }[];
}

const CASE_RFT_TYPE = 'Case-Rft';

export const CaseRftCreationForm: FunctionComponent<CaseRftFormProps> = ({
  updater,
  onClose,
  defaultConfidence,
  defaultCreatedBy,
  defaultMarkingDefinitions,
}) => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const navigate = useNavigate();
  const [mapAfter, setMapAfter] = useState<boolean>(false);
  const basicShape = {
    name: Yup.string().trim().min(2).required(t_i18n('This field is required')),
    description: Yup.string().nullable(),
    content: Yup.string().nullable(),
  };
  const caseRftValidator = useSchemaCreationValidation(
    CASE_RFT_TYPE,
    basicShape,
  );
  const [commit] = useApiMutation<CaseRftCreationCaseMutation>(
    caseRftMutation,
    undefined,
    { successMessage: `${t_i18n('entity_Case-Rft')} ${t_i18n('successfully created')}` },
  );

  const onSubmit: FormikConfig<FormikCaseRftAddInput>['onSubmit'] = (
    values,
    { setSubmitting, setErrors, resetForm },
  ) => {
    const input: CaseRftAddInput = {
      name: values.name,
      description: values.description,
      content: values.content,
      created: values.created,
      takedown_types: values.takedown_types,
      severity: values.severity,
      priority: values.priority,
      caseTemplates: values.caseTemplates?.map(({ value }) => value),
      confidence: parseInt(String(values.confidence), 10),
      objectAssignee: values.objectAssignee.map(({ value }) => value),
      objectParticipant: values.objectParticipant.map(({ value }) => value),
      objectMarking: values.objectMarking.map(({ value }) => value),
      objectLabel: values.objectLabel.map(({ value }) => value),
      externalReferences: values.externalReferences.map(({ value }) => value),
      createdBy: values.createdBy?.value,
      file: values.file,
    };
    commit({
      variables: {
        input,
      },
      updater: (store, response) => {
        if (updater && response) {
          updater(store, 'caseRftAdd', response.caseRftAdd);
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
            `/dashboard/cases/rfts/${response.caseRftAdd?.id}/content/mapping`,
          );
        }
      },
    });
  };

  const initialValues = useDefaultValues<FormikCaseRftAddInput>(CASE_RFT_TYPE, {
    name: '',
    confidence: defaultConfidence,
    description: '',
    content: '',
    created: null,
    takedown_types: [],
    caseTemplates: [],
    severity: '',
    priority: '',
    createdBy: defaultCreatedBy,
    objectMarking: defaultMarkingDefinitions ?? [],
    objectAssignee: [],
    objectParticipant: [],
    objectLabel: [],
    externalReferences: [],
    file: undefined,
  });

  return (
    <Formik<FormikCaseRftAddInput>
      initialValues={initialValues}
      validationSchema={caseRftValidator}
      onSubmit={onSubmit}
      onReset={onClose}
    >
      {({ submitForm, handleReset, isSubmitting, setFieldValue, values }) => (
        <Form style={{ margin: '20px 0 20px 0' }}>
          <Field
            component={TextField}
            variant="standard"
            name="name"
            label={t_i18n('Name')}
            fullWidth={true}
            detectDuplicate={['Case-Rft']}
          />
          <Field
            component={DateTimePickerField}
            name="created"
            textFieldProps={{
              label: t_i18n('Request For Takedown Date'),
              variant: 'standard',
              fullWidth: true,
              style: { marginTop: 20 },
            }}
          />
          <OpenVocabField
            label={t_i18n('Request for takedown type')}
            type="request_for_takedown_types_ov"
            name="takedown_types"
            multiple
            onChange={setFieldValue}
            containerStyle={fieldSpacingContainerStyle}
          />
          <OpenVocabField
            label={t_i18n('Severity')}
            type="case_severity_ov"
            name="severity"
            onChange={(name, value) => setFieldValue(name, value)}
            containerStyle={fieldSpacingContainerStyle}
          />
          <OpenVocabField
            label={t_i18n('Priority')}
            type="case_priority_ov"
            name="priority"
            onChange={(name, value) => setFieldValue(name, value)}
            containerStyle={fieldSpacingContainerStyle}
          />
          <CaseTemplateField
            onChange={setFieldValue}
            containerStyle={fieldSpacingContainerStyle}
          />
          <ConfidenceField
            entityType="Case-Rft"
            containerStyle={fieldSpacingContainerStyle}
          />
          <Field
            component={MarkdownField}
            name="description"
            label={t_i18n('Description')}
            fullWidth={true}
            multiline={true}
            rows="4"
            style={fieldSpacingContainerStyle}
          />
          <Field
            component={RichTextField}
            name="content"
            label={t_i18n('Content')}
            fullWidth={true}
            style={{
              ...fieldSpacingContainerStyle,
              minHeight: 200,
              height: 200,
            }}
          />
          <ObjectAssigneeField
            name="objectAssignee"
            style={fieldSpacingContainerStyle}
          />
          <ObjectParticipantField
            name="objectParticipant"
            style={fieldSpacingContainerStyle}
          />
          <CreatedByField
            name="createdBy"
            style={fieldSpacingContainerStyle}
            setFieldValue={setFieldValue}
          />
          <ObjectLabelField
            name="objectLabel"
            style={fieldSpacingContainerStyle}
            setFieldValue={setFieldValue}
            values={values.objectLabel}
          />
          <ObjectMarkingField
            name="objectMarking"
            style={fieldSpacingContainerStyle}
            setFieldValue={setFieldValue}
          />
          <ExternalReferencesField
            name="externalReferences"
            style={fieldSpacingContainerStyle}
            setFieldValue={setFieldValue}
            values={values.externalReferences}
          />
          <CustomFileUploader setFieldValue={setFieldValue} />
          <div className={classes.buttons}>
            <Button
              variant="contained"
              onClick={handleReset}
              disabled={isSubmitting}
              classes={{ root: classes.button }}
            >
              {t_i18n('Cancel')}
            </Button>
            <Button
              variant="contained"
              color="secondary"
              onClick={submitForm}
              disabled={isSubmitting}
              classes={{ root: classes.button }}
            >
              {t_i18n('Create')}
            </Button>
            {values.content.length > 0 && (
              <Button
                variant="contained"
                color="success"
                onClick={() => {
                  setMapAfter(true);
                  submitForm();
                }}
                disabled={isSubmitting}
                classes={{ root: classes.button }}
              >
                {t_i18n('Create and map')}
              </Button>
            )}
          </div>
        </Form>
      )}
    </Formik>
  );
};

const CaseRftCreation = ({
  paginationOptions,
}: {
  paginationOptions: CaseRftsLinesCasesPaginationQuery$variables;
}) => {
  const { t_i18n } = useFormatter();
  const { isFeatureEnable } = useHelper();
  const updater = (store: RecordSourceSelectorProxy) => insertNode(
    store,
    'Pagination_case_caseRfts',
    paginationOptions,
    'caseRftAdd',
  );
  const isFABReplaced = isFeatureEnable('FAB_REPLACEMENT');
  const CreateCaseRftControlledDial = (props: DrawerControlledDialProps) => (
    <CreateEntityControlledDial entityType='Case-Rft' {...props} />
  );

  return (
    <Drawer
      title={t_i18n('Create a request for takedown')}
      variant={isFABReplaced ? undefined : DrawerVariant.create}
      controlledDial={isFABReplaced ? CreateCaseRftControlledDial : undefined}
    >
      <CaseRftCreationForm updater={updater} />
    </Drawer>
  );
};

export default CaseRftCreation;
