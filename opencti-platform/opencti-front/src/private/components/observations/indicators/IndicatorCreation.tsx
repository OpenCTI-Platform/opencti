import React, { FunctionComponent, useState } from 'react';
import { Field, Form, Formik } from 'formik';
import Button from '@mui/material/Button';
import Fab from '@mui/material/Fab';
import { Add } from '@mui/icons-material';
import * as Yup from 'yup';
import { graphql } from 'react-relay';
import makeStyles from '@mui/styles/makeStyles';
import { RecordSourceSelectorProxy } from 'relay-runtime';
import { FormikConfig } from 'formik/dist/types';
import Dialog from '@mui/material/Dialog';
import DialogTitle from '@mui/material/DialogTitle';
import DialogContent from '@mui/material/DialogContent';
import Drawer, { DrawerControlledDialProps, DrawerVariant } from '@components/common/drawer/Drawer';
import { IndicatorsLinesPaginationQuery$variables } from '@components/observations/__generated__/IndicatorsLinesPaginationQuery.graphql';
import useHelper from 'src/utils/hooks/useHelper';
import { useFormatter } from '../../../../components/i18n';
import { handleErrorInForm } from '../../../../relay/environment';
import TextField from '../../../../components/TextField';
import CreatedByField from '../../common/form/CreatedByField';
import ObjectLabelField from '../../common/form/ObjectLabelField';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';
import TypesField from '../TypesField';
import SwitchField from '../../../../components/fields/SwitchField';
import MarkdownField from '../../../../components/fields/MarkdownField';
import KillChainPhasesField from '../../common/form/KillChainPhasesField';
import ConfidenceField from '../../common/form/ConfidenceField';
import { ExternalReferencesField } from '../../common/form/ExternalReferencesField';
import DateTimePickerField from '../../../../components/DateTimePickerField';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import OpenVocabField from '../../common/form/OpenVocabField';
import { insertNode } from '../../../../utils/store';
import type { Theme } from '../../../../components/Theme';
import { Option } from '../../common/form/ReferenceField';
import { IndicatorCreationMutation, IndicatorCreationMutation$variables } from './__generated__/IndicatorCreationMutation.graphql';
import { parse } from '../../../../utils/Time';
import useDefaultValues from '../../../../utils/hooks/useDefaultValues';
import { useSchemaCreationValidation } from '../../../../utils/hooks/useEntitySettings';
import CustomFileUploader from '../../common/files/CustomFileUploader';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import CreateEntityControlledDial from '../../../../components/CreateEntityControlledDial';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles<Theme>((theme) => ({
  createButtonContextual: {
    position: 'fixed',
    bottom: 30,
    right: 100,
    transition: theme.transitions.create('right', {
      easing: theme.transitions.easing.sharp,
      duration: theme.transitions.duration.enteringScreen,
    }),
  },
  buttons: {
    marginTop: 20,
    textAlign: 'right',
  },
  button: {
    marginLeft: theme.spacing(2),
  },
}));

const indicatorMutation = graphql`
  mutation IndicatorCreationMutation($input: IndicatorAddInput!) {
    indicatorAdd(input: $input) {
      id
      standard_id
      name
      description
      entity_type
      parent_types
      ...IndicatorsLine_node
    }
  }
`;

const INDICATOR_TYPE = 'Indicator';

interface IndicatorAddInput {
  name: string
  confidence: number | undefined
  indicator_types: string[]
  pattern: string
  pattern_type: string
  x_opencti_main_observable_type: string
  createObservables: boolean
  x_mitre_platforms: string[];
  valid_from: Date | null
  valid_until: Date | null
  description: string
  createdBy: Option | undefined
  objectMarking: Option[]
  killChainPhases: Option[]
  objectLabel: Option[]
  externalReferences: { value: string }[]
  x_opencti_detection: boolean
  x_opencti_score: number
  file: File | undefined
}

interface IndicatorFormProps {
  updater: (store: RecordSourceSelectorProxy, key: string) => void
  onReset?: () => void;
  onCompleted?: () => void;
  defaultCreatedBy?: { value: string, label: string }
  defaultMarkingDefinitions?: { value: string, label: string }[]
  defaultConfidence?: number;
  inputValue?: string;
}

export const IndicatorCreationForm: FunctionComponent<IndicatorFormProps> = ({
  updater,
  onReset,
  onCompleted,
  defaultConfidence,
  defaultCreatedBy,
  defaultMarkingDefinitions,
}) => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const basicShape = {
    name: Yup.string().trim().min(2).required(t_i18n('This field is required')),
    indicator_types: Yup.array().nullable(),
    confidence: Yup.number().nullable(),
    pattern: Yup.string().trim().required(t_i18n('This field is required')),
    pattern_type: Yup.string().trim().required(t_i18n('This field is required')),
    x_opencti_main_observable_type: Yup.string().trim().required(
      t_i18n('This field is required'),
    ),
    valid_from: Yup.date()
      .nullable()
      .typeError(t_i18n('The value must be a datetime (yyyy-MM-dd hh:mm (a|p)m)')),
    valid_until: Yup.date()
      .nullable()
      .typeError(t_i18n('The value must be a datetime (yyyy-MM-dd hh:mm (a|p)m)'))
      .test('is-greater', t_i18n('The valid until date must be greater than the valid from date'), function isGreater(value) {
        const { valid_from } = this.parent;
        return !valid_from || !value || value > valid_from;
      }),
    x_mitre_platforms: Yup.array().nullable(),
    x_opencti_score: Yup.number().nullable(),
    description: Yup.string().nullable(),
    x_opencti_detection: Yup.boolean().nullable(),
    createObservables: Yup.boolean().nullable(),
  };
  const indicatorValidator = useSchemaCreationValidation(
    INDICATOR_TYPE,
    basicShape,
  );

  const [commit] = useApiMutation<IndicatorCreationMutation>(
    indicatorMutation,
    undefined,
    { successMessage: `${t_i18n('entity_Indicator')} ${t_i18n('successfully created')}` },
  );

  const onSubmit: FormikConfig<IndicatorAddInput>['onSubmit'] = (values, { setSubmitting, setErrors, resetForm }) => {
    const input: IndicatorCreationMutation$variables['input'] = {
      name: values.name,
      description: values.description,
      indicator_types: values.indicator_types,
      pattern: values.pattern,
      pattern_type: values.pattern_type,
      createObservables: values.createObservables,
      x_opencti_main_observable_type: values.x_opencti_main_observable_type,
      x_mitre_platforms: values.x_mitre_platforms,
      confidence: parseInt(String(values.confidence), 10),
      x_opencti_score: parseInt(String(values.x_opencti_score), 10),
      x_opencti_detection: values.x_opencti_detection,
      valid_from: values.valid_from ? parse(values.valid_from).format() : null,
      valid_until: values.valid_until ? parse(values.valid_until).format() : null,
      killChainPhases: (values.killChainPhases ?? []).map(({ value }) => value),
      createdBy: values.createdBy?.value,
      objectMarking: values.objectMarking.map((v) => v.value),
      objectLabel: values.objectLabel.map((v) => v.value),
      externalReferences: values.externalReferences.map(({ value }) => value),
      file: values.file,
    };
    commit({
      variables: {
        input,
      },
      updater: (store) => {
        if (updater) {
          updater(store, 'indicatorAdd');
        }
      },
      onError: (error) => {
        handleErrorInForm(error, setErrors);
        setSubmitting(false);
      },
      onCompleted: () => {
        setSubmitting(false);
        resetForm();
        if (onCompleted) {
          onCompleted();
        }
      },
    });
  };

  const initialValues = useDefaultValues(
    INDICATOR_TYPE,
    {
      name: '',
      confidence: defaultConfidence,
      indicator_types: [],
      pattern: '',
      pattern_type: '',
      x_opencti_main_observable_type: '',
      x_mitre_platforms: [],
      valid_from: null,
      valid_until: null,
      description: '',
      createdBy: defaultCreatedBy,
      objectMarking: defaultMarkingDefinitions ?? [],
      killChainPhases: [],
      objectLabel: [],
      externalReferences: [],
      x_opencti_detection: false,
      createObservables: false,
      x_opencti_score: 50,
      file: undefined,
    },
  );

  return (
    <Formik
      initialValues={initialValues}
      validationSchema={indicatorValidator}
      onSubmit={onSubmit}
      onReset={onReset}
    >
      {({ submitForm, handleReset, isSubmitting, setFieldValue, values }) => (
        <Form style={{ margin: '20px 0 20px 0' }}>
          <Field
            component={TextField}
            variant="standard"
            name="name"
            label={t_i18n('Name')}
            fullWidth={true}
          />
          <OpenVocabField
            label={t_i18n('Indicator types')}
            type="indicator-type-ov"
            name="indicator_types"
            multiple={true}
            containerStyle={fieldSpacingContainerStyle}
            onChange={(n, v) => setFieldValue(n, v)}
          />
          <ConfidenceField
            entityType="Indicator"
            containerStyle={fieldSpacingContainerStyle}
          />
          <OpenVocabField
            label={t_i18n('Pattern type')}
            type="pattern_type_ov"
            name="pattern_type"
            onChange={(name, value) => setFieldValue(name, value)}
            containerStyle={fieldSpacingContainerStyle}
            multiple={false}
          />
          <Field
            component={TextField}
            variant="standard"
            name="pattern"
            label={t_i18n('Pattern')}
            fullWidth={true}
            multiline={true}
            rows="4"
            style={{ marginTop: 20 }}
            detectDuplicate={['Indicator']}
          />
          <TypesField
            name="x_opencti_main_observable_type"
            label={t_i18n('Main observable type')}
            containerstyle={fieldSpacingContainerStyle}
          />
          <Field
            component={DateTimePickerField}
            name="valid_from"
            textFieldProps={{
              label: t_i18n('Valid from'),
              variant: 'standard',
              fullWidth: true,
              style: { marginTop: 20 },
            }}
          />
          <Field
            component={DateTimePickerField}
            name="valid_until"
            textFieldProps={{
              label: t_i18n('Valid until'),
              variant: 'standard',
              fullWidth: true,
              style: { marginTop: 20 },
            }}
          />
          <OpenVocabField
            label={t_i18n('Platforms')}
            type="platforms_ov"
            name="x_mitre_platforms"
            onChange={(name, value) => setFieldValue(name, value)}
            containerStyle={fieldSpacingContainerStyle}
            multiple={true}
          />
          <Field
            component={TextField}
            variant="standard"
            name="x_opencti_score"
            label={t_i18n('Score')}
            type="number"
            fullWidth={true}
            style={{ marginTop: 20 }}
          />
          <Field
            component={MarkdownField}
            name="description"
            label={t_i18n('Description')}
            fullWidth={true}
            multiline={true}
            rows="4"
            style={{ marginTop: 20 }}
          />
          <KillChainPhasesField
            name="killChainPhases"
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
          <Field
            component={SwitchField}
            type="checkbox"
            name="x_opencti_detection"
            label={t_i18n('Detection')}
            fullWidth={true}
            containerstyle={{ marginTop: 20 }}
          />
          <Field
            component={SwitchField}
            type="checkbox"
            name="createObservables"
            label={t_i18n('Create observables from this indicator')}
            fullWidth={true}
            containerstyle={{ marginTop: 10 }}
          />
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
          </div>
        </Form>
      )}
    </Formik>
  );
};

interface IndicatorCreationProps {
  paginationOptions: IndicatorsLinesPaginationQuery$variables,
  contextual?: boolean,
  display?: boolean
}

const IndicatorCreation: FunctionComponent<IndicatorCreationProps> = ({ paginationOptions, contextual, display }) => {
  const { t_i18n } = useFormatter();
  const { isFeatureEnable } = useHelper();
  const classes = useStyles();
  const [open, setOpen] = useState(false);
  const handleOpen = () => setOpen(true);
  const handleClose = () => setOpen(false);
  const onReset = () => handleClose();
  const isFABReplaced = isFeatureEnable('FAB_REPLACEMENT');
  const CreateIndicatorControlledDial = (props: DrawerControlledDialProps) => (
    <CreateEntityControlledDial entityType='Indicator' {...props} />
  );
  const updater = (store: RecordSourceSelectorProxy) => insertNode(
    store,
    'Pagination_indicators',
    paginationOptions,
    'indicatorAdd',
  );

  if (contextual) {
    return (
      <div style={{ visibility: !display ? 'hidden' : 'visible' }}>
        <Fab
          onClick={handleOpen}
          color="primary"
          aria-label="Add"
          className={classes.createButtonContextual}
          sx={{ zIndex: 1203 }}
        >
          <Add />
        </Fab>
        <Dialog
          open={open}
          onClose={handleClose}
          PaperProps={{ elevation: 1 }}
        >
          <DialogTitle>{t_i18n('Create an indicator')}</DialogTitle>
          <DialogContent>
            <IndicatorCreationForm
              updater={updater}
              onCompleted={handleClose}
              onReset={onReset}
            />
          </DialogContent>
        </Dialog>
      </div>
    );
  }

  return (
    <Drawer
      title={t_i18n('Create an indicator')}
      variant={isFABReplaced ? undefined : DrawerVariant.create}
      controlledDial={isFABReplaced ? CreateIndicatorControlledDial : undefined}
    >
      {({ onClose }) => (
        <IndicatorCreationForm
          updater={updater}
          onCompleted={onClose}
          onReset={onClose}
        />
      )}
    </Drawer>
  );
};

export default IndicatorCreation;
