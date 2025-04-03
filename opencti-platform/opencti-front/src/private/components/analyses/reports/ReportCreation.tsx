import React, { FunctionComponent, useState } from 'react';
import { Field, Form, Formik } from 'formik';
import Button from '@mui/material/Button';
import * as Yup from 'yup';
import { graphql } from 'react-relay';
import makeStyles from '@mui/styles/makeStyles';
import { FormikConfig } from 'formik/dist/types';
import { RecordSourceSelectorProxy } from 'relay-runtime';
import { useNavigate } from 'react-router-dom';
import Drawer, { DrawerControlledDialProps, DrawerVariant } from '@components/common/drawer/Drawer';
import useHelper from 'src/utils/hooks/useHelper';
import { ReportsLinesPaginationQuery$variables } from '@components/analyses/__generated__/ReportsLinesPaginationQuery.graphql';
import AuthorizedMembersField from '@components/common/form/AuthorizedMembersField';
import Typography from '@mui/material/Typography';
import AccordionDetails from '@mui/material/AccordionDetails';
import { useFormatter } from '../../../../components/i18n';
import { handleErrorInForm } from '../../../../relay/environment';
import TextField from '../../../../components/TextField';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';
import ObjectLabelField from '../../common/form/ObjectLabelField';
import CreatedByField from '../../common/form/CreatedByField';
import MarkdownField from '../../../../components/fields/MarkdownField';
import ConfidenceField from '../../common/form/ConfidenceField';
import { ExternalReferencesField } from '../../common/form/ExternalReferencesField';
import DateTimePickerField from '../../../../components/DateTimePickerField';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import OpenVocabField from '../../common/form/OpenVocabField';
import { insertNode } from '../../../../utils/store';
import ObjectAssigneeField from '../../common/form/ObjectAssigneeField';
import { Option } from '../../common/form/ReferenceField';
import type { Theme } from '../../../../components/Theme';
import { ReportCreationMutation, ReportCreationMutation$variables } from './__generated__/ReportCreationMutation.graphql';
import useDefaultValues from '../../../../utils/hooks/useDefaultValues';
import RichTextField from '../../../../components/fields/RichTextField';
import ObjectParticipantField from '../../common/form/ObjectParticipantField';
import CustomFileUploader from '../../common/files/CustomFileUploader';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import CreateEntityControlledDial from '../../../../components/CreateEntityControlledDial';
import { useDynamicSchemaCreationValidation, useIsMandatoryAttribute, yupShapeConditionalRequired } from '../../../../utils/hooks/useEntitySettings';
import useGranted, { KNOWLEDGE_KNUPDATE_KNMANAGEAUTHMEMBERS } from '../../../../utils/hooks/useGranted';
import Security from '../../../../utils/Security';
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

export const reportCreationMutation = graphql`
  mutation ReportCreationMutation($input: ReportAddInput!) {
    reportAdd(input: $input) {
      id
      standard_id
      name
      representative {
        main
      }
      description
      entity_type
      confidence
      parent_types
      ...ReportsLine_node
    }
  }
`;

const REPORT_TYPE = 'Report';

interface ReportAddInput {
  name: string;
  description: string;
  content: string;
  published: Date | null;
  confidence: number | undefined;
  report_types: string[];
  x_opencti_reliability: string | undefined
  createdBy: Option | undefined;
  objectMarking: Option[];
  objectLabel: Option[];
  objectAssignee: { value: string }[];
  objectParticipant: Option[];
  externalReferences: { value: string }[];
  file: File | undefined;
  authorized_members: {
    value: string,
    accessRight: string,
    groupsRestriction: {
      label: string,
      value: string,
      type: string
    }[] }[] | undefined;
}

interface ReportFormProps {
  updater: (
    store: RecordSourceSelectorProxy,
    key: string,
    response: { id: string; name: string } | null | undefined
  ) => void;
  onClose?: () => void;
  defaultCreatedBy?: { value: string; label: string };
  defaultMarkingDefinitions?: { value: string; label: string }[];
  defaultConfidence?: number;
  inputValue?: string;
}

export const ReportCreationForm: FunctionComponent<ReportFormProps> = ({
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
  const { mandatoryAttributes } = useIsMandatoryAttribute(REPORT_TYPE);
  const canEditAuthorizedMembers = useGranted([KNOWLEDGE_KNUPDATE_KNMANAGEAUTHMEMBERS]);
  const isEnterpriseEdition = useEnterpriseEdition();

  const basicShape = yupShapeConditionalRequired({
    name: Yup.string().trim().min(2, t_i18n('Name must be at least 2 characters')),
    published: Yup.date().typeError(t_i18n('The value must be a datetime (yyyy-MM-dd hh:mm (a|p)m)')),
    report_types: Yup.array().nullable(),
    x_opencti_reliability: Yup.string().nullable(),
    confidence: Yup.number().nullable(),
    description: Yup.string().nullable(),
    content: Yup.string().nullable(),
    objectAssignee: Yup.array().nullable(),
    objectParticipant: Yup.array().nullable(),
    objectLabel: Yup.array().nullable(),
    objectMarking: Yup.array().nullable(),
    externalReferences: Yup.array().nullable(),
    file: Yup.mixed().nullable(),
    authorized_members: Yup.array().nullable(),
  }, mandatoryAttributes);
  const reportValidator = useDynamicSchemaCreationValidation(
    mandatoryAttributes,
    basicShape,
  );
  const [commit] = useApiMutation<ReportCreationMutation>(
    reportCreationMutation,
    undefined,
    { successMessage: `${t_i18n('entity_Report')} ${t_i18n('successfully created')}` },
  );
  const onSubmit: FormikConfig<ReportAddInput>['onSubmit'] = (
    values,
    { setSubmitting, setErrors, resetForm },
  ) => {
    const input: ReportCreationMutation$variables['input'] = {
      name: values.name,
      description: values.description,
      content: values.content,
      published: values.published,
      confidence: parseInt(String(values.confidence), 10),
      report_types: values.report_types,
      x_opencti_reliability: values.x_opencti_reliability,
      createdBy: values.createdBy?.value,
      objectMarking: values.objectMarking.map((v) => v.value),
      objectAssignee: values.objectAssignee.map(({ value }) => value),
      objectParticipant: values.objectParticipant.map(({ value }) => value),
      objectLabel: values.objectLabel.map((v) => v.value),
      externalReferences: values.externalReferences.map(({ value }) => value),
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
          updater(store, 'reportAdd', response.reportAdd);
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
            `/dashboard/analyses/reports/${response.reportAdd?.id}/content/mapping`,
          );
        }
      },
    });
  };
  const initialValues = useDefaultValues<ReportAddInput>(REPORT_TYPE, {
    name: inputValue ?? '',
    published: null,
    report_types: [],
    x_opencti_reliability: undefined,
    confidence: defaultConfidence,
    description: '',
    content: '',
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
    <Formik<ReportAddInput>
      initialValues={initialValues}
      validationSchema={reportValidator}
      validateOnChange={true}
      validateOnBlur={true}
      onSubmit={onSubmit}
      onReset={onClose}
    >
      {({ submitForm, handleReset, isSubmitting, setFieldValue, values }) => (
        <Form>
          <Field
            component={TextField}
            name="name"
            label={t_i18n('Name')}
            required={mandatoryAttributes.includes('name')}
            detectDuplicate={['Report']}
            fullWidth
            askAi
          />
          <Field
            component={DateTimePickerField}
            name="published"
            textFieldProps={{
              label: t_i18n('Publication date'),
              required: mandatoryAttributes.includes('published'),
              variant: 'standard',
              fullWidth: true,
              style: { ...fieldSpacingContainerStyle },
            }}
          />
          <OpenVocabField
            label={t_i18n('Report types')}
            type="report_types_ov"
            name="report_types"
            required={mandatoryAttributes.includes('report_types')}
            onChange={(name, value) => setFieldValue(name, value)}
            containerStyle={fieldSpacingContainerStyle}
            multiple={true}
          />
          <OpenVocabField
            label={t_i18n('Reliability')}
            type="reliability_ov"
            name="x_opencti_reliability"
            required={mandatoryAttributes.includes('x_opencti_reliability')}
            containerStyle={fieldSpacingContainerStyle}
            multiple={false}
            onChange={setFieldValue}
          />
          <ConfidenceField
            entityType="Report"
            containerStyle={fieldSpacingContainerStyle}
          />
          <Field
            component={MarkdownField}
            name="description"
            label={t_i18n('Description')}
            required={mandatoryAttributes.includes('description')}
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
            required={mandatoryAttributes.includes('content')}
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
            required={mandatoryAttributes.includes('objectAssignee')}
          />
          <ObjectParticipantField
            name="objectParticipant"
            style={fieldSpacingContainerStyle}
            required={mandatoryAttributes.includes('objectParticipant')}
          />
          <CreatedByField
            name="createdBy"
            required={mandatoryAttributes.includes('createdBy')}
            style={fieldSpacingContainerStyle}
            setFieldValue={setFieldValue}
          />
          <ObjectLabelField
            name="objectLabel"
            required={mandatoryAttributes.includes('objectLabel')}
            style={fieldSpacingContainerStyle}
            setFieldValue={setFieldValue}
            values={values.objectLabel}
          />
          <ObjectMarkingField
            name="objectMarking"
            required={mandatoryAttributes.includes('objectMarking')}
            style={fieldSpacingContainerStyle}
            setFieldValue={setFieldValue}

          />
          <ExternalReferencesField
            name="externalReferences"
            required={mandatoryAttributes.includes('externalReferences')}
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
                <Accordion>
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

const ReportCreation = ({
  paginationOptions,
}: {
  paginationOptions: ReportsLinesPaginationQuery$variables;
}) => {
  const { t_i18n } = useFormatter();
  const { isFeatureEnable } = useHelper();
  const isFABReplaced = isFeatureEnable('FAB_REPLACEMENT');
  const updater = (store: RecordSourceSelectorProxy) => insertNode(
    store,
    'Pagination_reports',
    paginationOptions,
    'reportAdd',
  );
  const CreateReportControlledDial = (props: DrawerControlledDialProps) => (
    <CreateEntityControlledDial entityType='Report' {...props} />
  );
  return (
    <Drawer
      title={t_i18n('Create a report')}
      variant={isFABReplaced ? undefined : DrawerVariant.create}
      controlledDial={isFABReplaced ? CreateReportControlledDial : undefined}
    >
      <ReportCreationForm updater={updater} />
    </Drawer>
  );
};

export default ReportCreation;
