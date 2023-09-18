import React, { FunctionComponent, useState } from 'react';
import { Field, Form, Formik } from 'formik';
import Button from '@mui/material/Button';
import * as Yup from 'yup';
import { graphql, useMutation } from 'react-relay';
import makeStyles from '@mui/styles/makeStyles';
import { FormikConfig } from 'formik/dist/types';
import { RecordSourceSelectorProxy } from 'relay-runtime';
import { useHistory } from 'react-router-dom';
import Drawer, { DrawerVariant } from '@components/common/drawer/Drawer';
import { useFormatter } from '../../../../components/i18n';
import { handleErrorInForm } from '../../../../relay/environment';
import TextField from '../../../../components/TextField';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';
import ObjectLabelField from '../../common/form/ObjectLabelField';
import CreatedByField from '../../common/form/CreatedByField';
import MarkdownField from '../../../../components/MarkdownField';
import ConfidenceField from '../../common/form/ConfidenceField';
import { ExternalReferencesField } from '../../common/form/ExternalReferencesField';
import DateTimePickerField from '../../../../components/DateTimePickerField';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import OpenVocabField from '../../common/form/OpenVocabField';
import { insertNode } from '../../../../utils/store';
import ObjectAssigneeField from '../../common/form/ObjectAssigneeField';
import { useSchemaCreationValidation } from '../../../../utils/hooks/useEntitySettings';
import { ReportsLinesPaginationQuery$variables } from './__generated__/ReportsLinesPaginationQuery.graphql';
import { Option } from '../../common/form/ReferenceField';
import { Theme } from '../../../../components/Theme';
import { ReportCreationMutation, ReportCreationMutation$variables } from './__generated__/ReportCreationMutation.graphql';
import useDefaultValues from '../../../../utils/hooks/useDefaultValues';
import RichTextField from '../../../../components/RichTextField';
import ObjectParticipantField from '../../common/form/ObjectParticipantField';
import CustomFileUploader from '../../common/files/CustomFileUploader';

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
      description
      entity_type
      parent_types
      ...ReportLine_node
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
}

interface ReportFormProps {
  updater: (
    store: RecordSourceSelectorProxy,
    key: string,
    response: { id: string; name: string } | null
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
  const { t } = useFormatter();
  const history = useHistory();
  const [mapAfter, setMapAfter] = useState<boolean>(false);
  const basicShape = {
    name: Yup.string().min(2).required(t('This field is required')),
    published: Yup.date()
      .typeError(t('The value must be a datetime (yyyy-MM-dd hh:mm (a|p)m)'))
      .required(t('This field is required')),
    report_types: Yup.array().nullable(),
    x_opencti_reliability: Yup.string().nullable(),
    confidence: Yup.number().nullable(),
    description: Yup.string().nullable(),
    content: Yup.string().nullable(),
  };
  const reportValidator = useSchemaCreationValidation(REPORT_TYPE, basicShape);
  const [commit] = useMutation<ReportCreationMutation>(reportCreationMutation);
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
    };
    commit({
      variables: {
        input,
      },
      updater: (store, response) => {
        if (updater) {
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
          history.push(
            `/dashboard/analyses/reports/${response.reportAdd?.id}/knowledge/content`,
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
  });
  return (
    <Formik<ReportAddInput>
      initialValues={initialValues}
      validationSchema={reportValidator}
      onSubmit={onSubmit}
      onReset={onClose}
    >
      {({ submitForm, handleReset, isSubmitting, setFieldValue, values }) => (
        <Form style={{ margin: '20px 0 20px 0' }}>
          <Field
            component={TextField}
            name="name"
            label={t('Name')}
            fullWidth={true}
          />
          <Field
            component={DateTimePickerField}
            name="published"
            TextFieldProps={{
              label: t('Publication date'),
              fullWidth: true,
              style: { marginTop: 20 },
            }}
          />
          <OpenVocabField
            label={t('Report types')}
            type="report_types_ov"
            name="report_types"
            onChange={(name, value) => setFieldValue(name, value)}
            containerStyle={fieldSpacingContainerStyle}
            multiple={true}
          />
          <OpenVocabField
            label={t('Reliability')}
            type="reliability_ov"
            name="x_opencti_reliability"
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
            label={t('Description')}
            fullWidth={true}
            multiline={true}
            rows="4"
            style={{ marginTop: 20 }}
          />
          <Field
            component={RichTextField}
            name="content"
            label={t('Content')}
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
              {t('Cancel')}
            </Button>
            <Button
              variant="contained"
              color="secondary"
              onClick={submitForm}
              disabled={isSubmitting}
              classes={{ root: classes.button }}
            >
              {t('Create')}
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
                {t('Create and map')}
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
  const { t } = useFormatter();
  const updater = (store: RecordSourceSelectorProxy) => insertNode(
    store,
    'Pagination_reports',
    paginationOptions,
    'reportAdd',
  );
  return (
    <Drawer
      title={t('Create a report')}
      variant={DrawerVariant.create}
    >
      <ReportCreationForm updater={updater} />
    </Drawer>
  );
};

export default ReportCreation;
