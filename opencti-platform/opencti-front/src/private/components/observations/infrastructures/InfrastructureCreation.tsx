import React, { FunctionComponent } from 'react';
import { Field, Form, Formik } from 'formik';
import Button from '@mui/material/Button';
import * as Yup from 'yup';
import { graphql, useMutation } from 'react-relay';
import makeStyles from '@mui/styles/makeStyles';
import { RecordSourceSelectorProxy } from 'relay-runtime';
import { FormikConfig } from 'formik/dist/types';
import Drawer from '@components/common/drawer/Drawer';
import { Add } from '@mui/icons-material';
import { useFormatter } from '../../../../components/i18n';
import { MESSAGING$, handleErrorInForm } from '../../../../relay/environment';
import TextField from '../../../../components/TextField';
import CreatedByField from '../../common/form/CreatedByField';
import ObjectLabelField from '../../common/form/ObjectLabelField';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';
import MarkdownField from '../../../../components/MarkdownField';
import { ExternalReferencesField } from '../../common/form/ExternalReferencesField';
import OpenVocabField from '../../common/form/OpenVocabField';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import ConfidenceField from '../../common/form/ConfidenceField';
import { parse } from '../../../../utils/Time';
import DateTimePickerField from '../../../../components/DateTimePickerField';
import KillChainPhasesField from '../../common/form/KillChainPhasesField';
import { useSchemaCreationValidation } from '../../../../utils/hooks/useEntitySettings';
import { insertNode } from '../../../../utils/store';
import type { Theme } from '../../../../components/Theme';
import { Option } from '../../common/form/ReferenceField';
import { InfrastructureCreationMutation, InfrastructureCreationMutation$variables } from './__generated__/InfrastructureCreationMutation.graphql';
import { InfrastructuresLinesPaginationQuery$variables } from './__generated__/InfrastructuresLinesPaginationQuery.graphql';
import useDefaultValues from '../../../../utils/hooks/useDefaultValues';
import CustomFileUploader from '../../common/files/CustomFileUploader';

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

const infrastructureMutation = graphql`
  mutation InfrastructureCreationMutation($input: InfrastructureAddInput!) {
    infrastructureAdd(input: $input) {
      id
      standard_id
      name
      description
      entity_type
      parent_types
      ...InfrastructureLine_node
    }
  }
`;

const INFRASTRUCTURE_TYPE = 'Infrastructure';

interface InfrastructureAddInput {
  name: string
  infrastructure_types: string[]
  confidence: number | undefined
  description: string
  createdBy: Option | undefined
  objectMarking: Option[]
  objectLabel: Option[]
  externalReferences: { value: string }[]
  first_seen: Date | null
  last_seen: Date | null
  killChainPhases: Option[]
  file: File | undefined
}

interface InfrastructureFormProps {
  updater: (store: RecordSourceSelectorProxy, key: string) => void
  onReset?: () => void;
  onCompleted?: () => void;
  defaultCreatedBy?: { value: string, label: string }
  defaultMarkingDefinitions?: { value: string, label: string }[]
  defaultConfidence?: number;
  inputValue?: string;
}

export const InfrastructureCreationForm: FunctionComponent<InfrastructureFormProps> = ({
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
    name: Yup.string().min(2).required(t_i18n('This field is required')),
    description: Yup.string().nullable(),
    infrastructure_types: Yup.array().nullable(),
    confidence: Yup.number().nullable(),
    first_seen: Yup.date()
      .nullable()
      .typeError(t_i18n('The value must be a datetime (yyyy-MM-dd hh:mm (a|p)m)')),
    last_seen: Yup.date()
      .nullable()
      .min(
        Yup.ref('first_seen'),
        'The last seen date can\'t be before first seen date',
      )
      .typeError(t_i18n('The value must be a datetime (yyyy-MM-dd hh:mm (a|p)m)')),
  };
  const infrastructureValidator = useSchemaCreationValidation(
    INFRASTRUCTURE_TYPE,
    basicShape,
  );

  const [commit] = useMutation<InfrastructureCreationMutation>(infrastructureMutation);

  const onSubmit: FormikConfig<InfrastructureAddInput>['onSubmit'] = (values, {
    setSubmitting,
    setErrors,
    resetForm,
  }) => {
    const input: InfrastructureCreationMutation$variables['input'] = {
      name: values.name,
      description: values.description,
      infrastructure_types: values.infrastructure_types,
      confidence: parseInt(String(values.confidence), 10),
      first_seen: values.first_seen ? parse(values.first_seen).format() : null,
      last_seen: values.first_seen ? parse(values.last_seen).format() : null,
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
          updater(store, 'infrastructureAdd');
        }
      },
      onError: (error) => {
        handleErrorInForm(error, setErrors);
        MESSAGING$.notifyError(`${error}`);
        setSubmitting(false);
      },
      onCompleted: () => {
        setSubmitting(false);
        resetForm();
        if (onCompleted) {
          onCompleted();
        }
        MESSAGING$.notifySuccess(`${t_i18n('entity_Infrastructure')} ${t_i18n('successfully created')}`);
      },
    });
  };

  const initialValues = useDefaultValues(
    INFRASTRUCTURE_TYPE,
    {
      name: '',
      infrastructure_types: [],
      confidence: defaultConfidence,
      description: '',
      createdBy: defaultCreatedBy,
      objectMarking: defaultMarkingDefinitions ?? [],
      objectLabel: [],
      externalReferences: [],
      first_seen: null,
      last_seen: null,
      killChainPhases: [],
      file: undefined,
    },
  );

  return (
    <Formik
      initialValues={initialValues}
      validationSchema={infrastructureValidator}
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
            detectDuplicate={['Infrastructure']}
          />
          <OpenVocabField
            label={t_i18n('Infrastructure types')}
            type="infrastructure-type-ov"
            name="infrastructure_types"
            containerStyle={fieldSpacingContainerStyle}
            multiple={true}
            onChange={(name, value) => setFieldValue(name, value)}
          />
          <ConfidenceField
            entityType="Infrastructure"
            containerStyle={{ width: '100%', marginTop: 20 }}
          />
          <Field
            component={DateTimePickerField}
            name="first_seen"
            textFieldProps={{
              label: t_i18n('First seen'),
              variant: 'standard',
              fullWidth: true,
              style: { marginTop: 20 },
            }}
          />
          <Field
            component={DateTimePickerField}
            name="last_seen"
            textFieldProps={{
              label: t_i18n('Last seen'),
              variant: 'standard',
              fullWidth: true,
              style: { marginTop: 20 },
            }}
          />
          <KillChainPhasesField
            name="killChainPhases"
            style={fieldSpacingContainerStyle}
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

const InfrastructureCreation = ({ paginationOptions }: {
  paginationOptions: InfrastructuresLinesPaginationQuery$variables
}) => {
  const { t_i18n } = useFormatter();
  const updater = (store: RecordSourceSelectorProxy) => insertNode(
    store,
    'Pagination_infrastructures',
    paginationOptions,
    'infrastructureAdd',
  );

  return (
    <Drawer
      title={t_i18n('Create an infrastructure')}
      controlledDial={({ onOpen }) => (
        <Button
          style={{
            marginLeft: '10px',
            padding: '7px 10px',
          }}
          color='primary'
          size='small'
          variant='contained'
          onClick={onOpen}
          aria-label={t_i18n('Add')}
        >
          {t_i18n('Create')} {t_i18n('entity_Infrastructure')} <Add />
        </Button>
      )}
    >
      {({ onClose }) => (
        <InfrastructureCreationForm
          updater={updater}
          onCompleted={onClose}
          onReset={onClose}
        />
      )}
    </Drawer>
  );
};

export default InfrastructureCreation;
