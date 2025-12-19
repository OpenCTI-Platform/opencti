import React, { FunctionComponent, useState } from 'react';
import { Field, Form, Formik } from 'formik';
import Button from '@common/button/Button';
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
import Drawer, { DrawerControlledDialProps } from '@components/common/drawer/Drawer';
import { IndicatorsLinesPaginationQuery$variables } from '@components/observations/__generated__/IndicatorsLinesPaginationQuery.graphql';
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
import { FieldOption, fieldSpacingContainerStyle } from '../../../../utils/field';
import OpenVocabField from '../../common/form/OpenVocabField';
import { insertNode } from '../../../../utils/store';
import type { Theme } from '../../../../components/Theme';
import { IndicatorCreationMutation, IndicatorCreationMutation$variables } from './__generated__/IndicatorCreationMutation.graphql';
import { parse } from '../../../../utils/Time';
import useDefaultValues from '../../../../utils/hooks/useDefaultValues';
import { useDynamicSchemaCreationValidation, useIsMandatoryAttribute, yupShapeConditionalRequired } from '../../../../utils/hooks/useEntitySettings';
import CustomFileUploader from '../../common/files/CustomFileUploader';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import CreateEntityControlledDial from '../../../../components/CreateEntityControlledDial';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles<Theme>((theme) => ({
  createButtonContextual: {
    position: 'fixed',
    bottom: 30,
    right: 30,
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
      representative {
        main
      }
      description
      entity_type
      parent_types
      ...IndicatorsLine_node
    }
  }
`;

const INDICATOR_TYPE = 'Indicator';

interface IndicatorAddInput {
  name: string;
  confidence: number | undefined;
  indicator_types: string[];
  pattern: string;
  pattern_type: string;
  x_opencti_main_observable_type: string;
  createObservables: boolean;
  x_mitre_platforms: string[];
  valid_from: Date | null;
  valid_until: Date | null;
  description: string;
  createdBy: FieldOption | undefined;
  objectMarking: FieldOption[];
  killChainPhases: FieldOption[];
  objectLabel: FieldOption[];
  externalReferences: { value: string }[];
  x_opencti_detection: boolean;
  x_opencti_score: number | undefined;
  file: File | undefined;
}

interface IndicatorFormProps {
  updater: (store: RecordSourceSelectorProxy, key: string) => void;
  onReset?: () => void;
  onCompleted?: () => void;
  defaultCreatedBy?: { value: string; label: string };
  defaultMarkingDefinitions?: { value: string; label: string }[];
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
  inputValue,
}) => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const { mandatoryAttributes } = useIsMandatoryAttribute(INDICATOR_TYPE);
  const basicShape = yupShapeConditionalRequired({
    name: Yup.string().trim().min(2),
    indicator_types: Yup.array().nullable(),
    confidence: Yup.number().nullable(),
    pattern: Yup.string(),
    pattern_type: Yup.string(),
    x_opencti_main_observable_type: Yup.string(),
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
    x_opencti_score: Yup.number().integer(t_i18n('The value must be an integer'))
      .nullable()
      .min(0, t_i18n('The value must be greater than or equal to 0'))
      .max(100, t_i18n('The value must be less than or equal to 100')),
    description: Yup.string().nullable(),
    x_opencti_detection: Yup.boolean().nullable(),
    createObservables: Yup.boolean().nullable(),
  }, mandatoryAttributes);
  const indicatorValidator = useDynamicSchemaCreationValidation(
    mandatoryAttributes,
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
      name: inputValue ?? '',
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
      x_opencti_score: undefined,
      file: undefined,
    },
  );

  return (
    <Formik<IndicatorAddInput>
      initialValues={initialValues}
      validationSchema={indicatorValidator}
      validateOnChange={true}
      validateOnBlur={true}
      onSubmit={onSubmit}
      onReset={onReset}
    >
      {({ submitForm, handleReset, isSubmitting, setFieldValue, values }) => (
        <Form>
          <Field
            component={TextField}
            variant="standard"
            name="name"
            label={t_i18n('Name')}
            required={(mandatoryAttributes.includes('name'))}
            fullWidth={true}
          />
          <OpenVocabField
            label={t_i18n('Indicator types')}
            type="indicator-type-ov"
            name="indicator_types"
            required={(mandatoryAttributes.includes('indicator_types'))}
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
            required={(mandatoryAttributes.includes('pattern_type'))}
            onChange={(name, value) => setFieldValue(name, value)}
            containerStyle={fieldSpacingContainerStyle}
            multiple={false}
          />
          <Field
            component={TextField}
            variant="standard"
            name="pattern"
            label={t_i18n('Pattern')}
            required={(mandatoryAttributes.includes('pattern'))}
            fullWidth={true}
            multiline={true}
            rows="4"
            style={fieldSpacingContainerStyle}
            detectDuplicate={['Indicator']}
          />
          <TypesField
            name="x_opencti_main_observable_type"
            label={t_i18n('Main observable type')}
            required={(mandatoryAttributes.includes('x_opencti_main_observable_type'))}
            containerstyle={fieldSpacingContainerStyle}
          />
          <Field
            component={DateTimePickerField}
            name="valid_from"
            textFieldProps={{
              label: t_i18n('Valid from'),
              required: (mandatoryAttributes.includes('valid_from')),
              variant: 'standard',
              fullWidth: true,
              style: { ...fieldSpacingContainerStyle },
            }}
          />
          <Field
            component={DateTimePickerField}
            name="valid_until"
            textFieldProps={{
              label: t_i18n('Valid until'),
              required: (mandatoryAttributes.includes('valid_until')),
              variant: 'standard',
              fullWidth: true,
              style: { ...fieldSpacingContainerStyle },
            }}
          />
          <OpenVocabField
            label={t_i18n('Platforms')}
            type="platforms_ov"
            name="x_mitre_platforms"
            required={(mandatoryAttributes.includes('x_mitre_platforms'))}
            onChange={(name, value) => setFieldValue(name, value)}
            containerStyle={fieldSpacingContainerStyle}
            multiple={true}
          />
          <Field
            component={TextField}
            variant="standard"
            name="x_opencti_score"
            label={t_i18n('Score')}
            required={(mandatoryAttributes.includes('x_opencti_score'))}
            type="number"
            fullWidth={true}
            style={fieldSpacingContainerStyle}
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
          <KillChainPhasesField
            name="killChainPhases"
            required={(mandatoryAttributes.includes('killChainPhases'))}
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
          />
          <ExternalReferencesField
            name="externalReferences"
            required={(mandatoryAttributes.includes('externalReferences'))}
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
              variant="secondary"
              onClick={handleReset}
              disabled={isSubmitting}
              classes={{ root: classes.button }}
            >
              {t_i18n('Cancel')}
            </Button>
            <Button
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
  paginationOptions: IndicatorsLinesPaginationQuery$variables;
  contextual?: boolean;
  display?: boolean;
}

const IndicatorCreation: FunctionComponent<IndicatorCreationProps> = ({ paginationOptions, contextual, display }) => {
  const { t_i18n } = useFormatter();
  const classes = useStyles();
  const [open, setOpen] = useState(false);
  const handleOpen = () => setOpen(true);
  const handleClose = () => setOpen(false);
  const onReset = () => handleClose();
  const CreateIndicatorControlledDial = (props: DrawerControlledDialProps) => (
    <CreateEntityControlledDial entityType="Indicator" {...props} />
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
          slotProps={{ paper: { elevation: 1 } }}
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
      controlledDial={CreateIndicatorControlledDial}
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
