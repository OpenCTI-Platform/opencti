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
import AuthorizedMembersField from '@components/common/form/AuthorizedMembersField';
import AccordionDetails from '@mui/material/AccordionDetails';
import Typography from '@mui/material/Typography';
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
import { CaseRftAddInput, CaseRftCreationCaseMutation } from './__generated__/CaseRftCreationCaseMutation.graphql';
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

const caseRftMutation = graphql`
  mutation CaseRftCreationCaseMutation($input: CaseRftAddInput!) {
    caseRftAdd(input: $input) {
      id
      standard_id
      entity_type
      parent_types
      name
      representative {
        main
      }
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
  authorized_members: {
    value: string,
    accessRight: string,
    groupsRestriction: {
      label: string,
      value: string,
      type: string
    }[] }[] | undefined;
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
  inputValue?: string;
}

const CASE_RFT_TYPE = 'Case-Rft';

export const CaseRftCreationForm: FunctionComponent<CaseRftFormProps> = ({
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
    CASE_RFT_TYPE,
  );
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
    name: inputValue ?? '',
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
    authorized_members: undefined,
  });
  if (!canEditAuthorizedMembers) {
    delete initialValues.authorized_members;
  }
  return (
    <Formik<FormikCaseRftAddInput>
      initialValues={initialValues}
      validationSchema={validator}
      validateOnChange={true}
      validateOnBlur={true}
      onSubmit={onSubmit}
      onReset={onClose}
    >
      {({ submitForm, handleReset, isSubmitting, setFieldValue, values, errors }) => (
        <Form>
          <Field
            component={TextField}
            variant="standard"
            name="name"
            required={(mandatoryAttributes.includes('name'))}
            label={t_i18n('Name')}
            fullWidth={true}
            detectDuplicate={['Case-Rft']}
          />
          <Field
            component={DateTimePickerField}
            name="created"
            required={(mandatoryAttributes.includes('created'))}
            textFieldProps={{
              label: t_i18n('Request For Takedown Date'),
              variant: 'standard',
              fullWidth: true,
              style: { ...fieldSpacingContainerStyle },
            }}
          />
          <OpenVocabField
            label={t_i18n('Request for takedown type')}
            type="request_for_takedown_types_ov"
            name="takedown_types"
            required={(mandatoryAttributes.includes('takedown_types'))}
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
            entityType="Case-Rft"
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
          />
          <Field
            component={RichTextField}
            name="content"
            label={t_i18n('Content')}
            required={(mandatoryAttributes.includes('content'))}
            meta={{ error: errors.content }}
            fullWidth={true}
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
