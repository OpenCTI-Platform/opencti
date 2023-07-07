import React, { FunctionComponent, useState } from 'react';
import { Field, Form, Formik } from 'formik';
import Drawer from '@mui/material/Drawer';
import Typography from '@mui/material/Typography';
import Button from '@mui/material/Button';
import IconButton from '@mui/material/IconButton';
import Fab from '@mui/material/Fab';
import { Add, Close } from '@mui/icons-material';
import * as Yup from 'yup';
import { graphql, useMutation } from 'react-relay';
import makeStyles from '@mui/styles/makeStyles';
import { SimpleFileUpload } from 'formik-mui';
import { FormikConfig } from 'formik/dist/types';
import { RecordSourceSelectorProxy } from 'relay-runtime';
import { useHistory } from 'react-router-dom';
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
import {
  ReportCreationMutation,
  ReportCreationMutation$variables,
} from './__generated__/ReportCreationMutation.graphql';
import useDefaultValues from '../../../../utils/hooks/useDefaultValues';
import RichTextField from '../../../../components/RichTextField';
import useAuth from '../../../../utils/hooks/useAuth';
import ObjectParticipantField from '../../common/form/ObjectParticipantField';

const useStyles = makeStyles<Theme>((theme) => ({
  drawerPaper: {
    minHeight: '100vh',
    width: '50%',
    position: 'fixed',
    overflow: 'auto',
    transition: theme.transitions.create('width', {
      easing: theme.transitions.easing.sharp,
      duration: theme.transitions.duration.enteringScreen,
    }),
    padding: 0,
  },
  createButton: {
    position: 'fixed',
    bottom: 30,
    right: 30,
  },
  buttons: {
    marginTop: 20,
    textAlign: 'right',
  },
  button: {
    marginLeft: theme.spacing(2),
  },
  header: {
    backgroundColor: theme.palette.background.nav,
    padding: '0 20px 20px 60px',
  },
  closeButton: {
    position: 'absolute',
    left: 5,
    color: 'inherit',
  },
  importButton: {
    position: 'absolute',
    top: 15,
    right: 20,
  },
  container: {
    padding: '10px 20px 20px 20px',
  },
  icon: {
    paddingTop: 4,
    display: 'inline-block',
    color: theme.palette.primary.main,
  },
  text: {
    display: 'inline-block',
    flexGrow: 1,
    marginLeft: 10,
  },
  autoCompleteIndicator: {
    display: 'none',
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
  onReset?: () => void;
  onCompleted?: () => void;
  defaultCreatedBy?: { value: string; label: string };
  defaultMarkingDefinitions?: { value: string; label: string }[];
  defaultConfidence?: number;
  inputValue?: string;
}

export const ReportCreationForm: FunctionComponent<ReportFormProps> = ({
  updater,
  onReset,
  onCompleted,
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
        if (onCompleted) {
          onCompleted();
        }
        if (mapAfter) {
          history.push(
            `/dashboard/analysis/reports/${response.reportAdd?.id}/knowledge/content`,
          );
        }
      },
    });
  };
  const initialValues = useDefaultValues<ReportAddInput>(REPORT_TYPE, {
    name: inputValue ?? '',
    published: null,
    report_types: [],
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
      onReset={onReset}
    >
      {({ submitForm, handleReset, isSubmitting, setFieldValue, values }) => (
        <Form style={{ margin: '20px 0 20px 0' }}>
          <Field
            component={TextField}
            variant="standard"
            name="name"
            label={t('Name')}
            fullWidth={true}
          />
          <Field
            component={DateTimePickerField}
            name="published"
            TextFieldProps={{
              label: t('Publication date'),
              variant: 'standard',
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
          <Field
            component={SimpleFileUpload}
            name="file"
            label={t('Associated file')}
            FormControlProps={{ style: { marginTop: 20, width: '100%' } }}
            InputLabelProps={{ fullWidth: true, variant: 'standard' }}
            InputProps={{ fullWidth: true, variant: 'standard' }}
            fullWidth={true}
          />
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
  const classes = useStyles();
  const {
    bannerSettings: { bannerHeightNumber },
  } = useAuth();
  const { t } = useFormatter();
  const [open, setOpen] = useState(false);
  const updater = (store: RecordSourceSelectorProxy) => insertNode(store, 'Pagination_reports', paginationOptions, 'reportAdd');
  return (
    <div>
      <Fab
        onClick={() => setOpen(true)}
        color="secondary"
        aria-label="Add"
        className={classes.createButton}
      >
        <Add />
      </Fab>
      <Drawer
        open={open}
        anchor="right"
        elevation={1}
        sx={{ zIndex: 1202 }}
        classes={{ paper: classes.drawerPaper }}
        onClose={() => setOpen(false)}
        disableEnforceFocus={true}
      >
        <div
          className={classes.header}
          style={{ paddingTop: bannerHeightNumber + 20 }}
        >
          <IconButton
            aria-label="Close"
            className={classes.closeButton}
            style={{ top: bannerHeightNumber + 12 }}
            onClick={() => setOpen(false)}
            size="large"
            color="primary"
          >
            <Close fontSize="small" color="primary" />
          </IconButton>
          <Typography variant="h6">{t('Create a report')}</Typography>
        </div>
        <div className={classes.container}>
          <ReportCreationForm
            updater={updater}
            onCompleted={() => setOpen(false)}
            onReset={() => setOpen(false)}
          />
        </div>
      </Drawer>
    </div>
  );
};

export default ReportCreation;
