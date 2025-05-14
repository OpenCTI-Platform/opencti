import Button from '@mui/material/Button';
import makeStyles from '@mui/styles/makeStyles';
import { Field, Form, Formik } from 'formik';
import { FormikConfig } from 'formik/dist/types';
import React, { FunctionComponent, useState } from 'react';
import { graphql } from 'react-relay';
import { RecordSourceSelectorProxy } from 'relay-runtime';
import * as Yup from 'yup';
import { useNavigate } from 'react-router-dom';
import Drawer, { DrawerControlledDialProps, DrawerVariant } from '@components/common/drawer/Drawer';
import { handleErrorInForm } from 'src/relay/environment';
import { CaseRfisLinesCasesPaginationQuery$variables } from '@components/cases/__generated__/CaseRfisLinesCasesPaginationQuery.graphql';
import AuthorizedMembersField from '@components/common/form/AuthorizedMembersField';
import Typography from '@mui/material/Typography';
import AccordionDetails from '@mui/material/AccordionDetails';
import DateTimePickerField from '../../../../components/DateTimePickerField';
import { useFormatter } from '../../../../components/i18n';
import MarkdownField from '../../../../components/fields/MarkdownField';
import TextField from '../../../../components/TextField';
import type { Theme } from '../../../../components/Theme';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import { useDynamicSchemaCreationValidation, useIsMandatoryAttribute, yupShapeConditionalRequired } from '../../../../utils/hooks/useEntitySettings';
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
import { CaseRfiAddInput, CaseRfiCreationCaseMutation } from './__generated__/CaseRfiCreationCaseMutation.graphql';
import useDefaultValues from '../../../../utils/hooks/useDefaultValues';
import RichTextField from '../../../../components/fields/RichTextField';
import ObjectParticipantField from '../../common/form/ObjectParticipantField';
import CustomFileUploader from '../../common/files/CustomFileUploader';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import useHelper from '../../../../utils/hooks/useHelper';
import CreateEntityControlledDial from '../../../../components/CreateEntityControlledDial';
import Security from '../../../../utils/Security';
import useGranted, { KNOWLEDGE_KNUPDATE_KNMANAGEAUTHMEMBERS } from '../../../../utils/hooks/useGranted';
import { Accordion, AccordionSummary } from '../../../../components/Accordion';
import useEnterpriseEdition from '../../../../utils/hooks/useEnterpriseEdition';

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

const caseRfiMutation = graphql`
  mutation CaseRfiCreationCaseMutation($input: CaseRfiAddInput!) {
    caseRfiAdd(input: $input) {
      id
      standard_id
      entity_type
      parent_types
      name
      representative {
        main
      }
      description
      ...CaseRfisLineCase_node
    }
  }
`;

interface FormikCaseRfiAddInput {
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
  information_types: string[];
  severity: string;
  priority: string;
  caseTemplates?: Option[];
  authorized_members: {
    value: string,
    accessRight: string,
    groupsRestriction: {
      label: string,
      value: string,
      type: string
    }[] }[] | undefined;
}

interface CaseRfiFormProps {
  updater: (
    store: RecordSourceSelectorProxy,
    key: string,
    response: { id: string; name: string } | null | undefined
  ) => void;
  onClose?: () => void;
  defaultConfidence?: number;
  defaultCreatedBy?: { value: string; label: string };
  defaultMarkingDefinitions?: { value: string; label: string }[];
  inputValue?: string;
}

const CASE_RFI_TYPE = 'Case-Rfi';

export const CaseRfiCreationForm: FunctionComponent<CaseRfiFormProps> = ({
  updater,
  onClose,
  defaultConfidence,
  defaultCreatedBy,
  defaultMarkingDefinitions,
  inputValue,
}) => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const navigate = useNavigate();
  const [mapAfter, setMapAfter] = useState<boolean>(false);
  const canEditAuthorizedMembers = useGranted([KNOWLEDGE_KNUPDATE_KNMANAGEAUTHMEMBERS]);
  const isEnterpriseEdition = useEnterpriseEdition();
  const { mandatoryAttributes } = useIsMandatoryAttribute(
    CASE_RFI_TYPE,
  );
  const basicShape = yupShapeConditionalRequired({
    name: Yup.string().trim().min(2),
    description: Yup.string().nullable(),
    authorized_members: Yup.array().nullable(),
  }, mandatoryAttributes);
  const validator = useDynamicSchemaCreationValidation(
    mandatoryAttributes,
    basicShape,
  );
  const [commit] = useApiMutation<CaseRfiCreationCaseMutation>(
    caseRfiMutation,
    undefined,
    { successMessage: `${t_i18n('entity_Case-Rfi')} ${t_i18n('successfully created')}` },
  );
  const onSubmit: FormikConfig<FormikCaseRfiAddInput>['onSubmit'] = (
    values,
    { setSubmitting, setErrors, resetForm },
  ) => {
    const input: CaseRfiAddInput = {
      name: values.name,
      description: values.description,
      content: values.content,
      created: values.created,
      information_types: values.information_types,
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
          updater(store, 'caseRfiAdd', response.caseRfiAdd);
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
            `/dashboard/cases/rfis/${response.caseRfiAdd?.id}/content/mapping`,
          );
        }
      },
    });
  };

  const initialValues = useDefaultValues<FormikCaseRfiAddInput>(CASE_RFI_TYPE, {
    name: inputValue ?? '',
    confidence: defaultConfidence,
    description: '',
    content: '',
    severity: '',
    priority: '',
    caseTemplates: [],
    created: null,
    information_types: [],
    createdBy: defaultCreatedBy,
    objectMarking: defaultMarkingDefinitions ?? [],
    objectAssignee: [],
    objectParticipant: [],
    objectLabel: [],
    externalReferences: [],
    file: undefined,
    authorized_members: undefined,
  });
  if (!canEditAuthorizedMembers) {
    delete initialValues.authorized_members;
  }
  return (
    <Formik<FormikCaseRfiAddInput>
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
            detectDuplicate={['Case-Rfi']}
            askAi={true}
          />
          <Field
            component={DateTimePickerField}
            name="created"
            textFieldProps={{
              label: t_i18n('Request For Information Date'),
              required: (mandatoryAttributes.includes('created')),
              variant: 'standard',
              fullWidth: true,
              style: { ...fieldSpacingContainerStyle },
            }}
          />
          <OpenVocabField
            label={t_i18n('Request for information type')}
            type="request_for_information_types_ov"
            name="information_types"
            required={(mandatoryAttributes.includes('information_types'))}
            multiple
            onChange={setFieldValue}
            containerStyle={fieldSpacingContainerStyle}
          />
          <OpenVocabField
            label={t_i18n('Severity')}
            type="case_severity_ov"
            name="severity"
            required={(mandatoryAttributes.includes('severity'))}
            onChange={(name, value) => setFieldValue(name, value)}
            containerStyle={fieldSpacingContainerStyle}
          />
          <OpenVocabField
            label={t_i18n('Priority')}
            type="case_priority_ov"
            name="priority"
            required={(mandatoryAttributes.includes('priority'))}
            onChange={(name, value) => setFieldValue(name, value)}
            containerStyle={fieldSpacingContainerStyle}
          />
          <CaseTemplateField
            onChange={setFieldValue}
            containerStyle={fieldSpacingContainerStyle}
          />
          <ConfidenceField
            entityType="Case-Rfi"
            containerStyle={fieldSpacingContainerStyle}
          />
          <Field
            component={MarkdownField}
            name="description"
            label={t_i18n('Description')}
            required={(mandatoryAttributes.includes('description'))}
            fullWidth={true}
            multiline={true}
            rows="4"
            style={fieldSpacingContainerStyle}
            askAi={true}
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
          {isEnterpriseEdition && (
            <Security
              needs={[KNOWLEDGE_KNUPDATE_KNMANAGEAUTHMEMBERS]}
            >
              <div style={fieldSpacingContainerStyle}>
                <Accordion >
                  <AccordionSummary id="accordion-panel">
                    <Typography>{t_i18n('Advanced options')}</Typography>
                  </AccordionSummary>
                  <AccordionDetails>
                    <Field
                      name={'authorized_members'}
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

const CaseRfiCreation = ({
  paginationOptions,
}: {
  paginationOptions: CaseRfisLinesCasesPaginationQuery$variables;
}) => {
  const { t_i18n } = useFormatter();
  const { isFeatureEnable } = useHelper();
  const updater = (store: RecordSourceSelectorProxy) => insertNode(
    store,
    'Pagination_case_caseRfis',
    paginationOptions,
    'caseRfiAdd',
  );
  const isFABReplaced = isFeatureEnable('FAB_REPLACEMENT');
  const CreateCaseRfiControlledDial = (props: DrawerControlledDialProps) => (
    <CreateEntityControlledDial entityType='Case-Rfi' {...props} />
  );

  return (
    <Drawer
      title={t_i18n('Create a request for information')}
      variant={isFABReplaced ? undefined : DrawerVariant.create}
      controlledDial={isFABReplaced ? CreateCaseRfiControlledDial : undefined}
    >
      <CaseRfiCreationForm updater={updater} />
    </Drawer>
  );
};

export default CaseRfiCreation;
