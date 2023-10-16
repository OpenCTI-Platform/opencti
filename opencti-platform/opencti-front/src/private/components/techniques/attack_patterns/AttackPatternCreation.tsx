import React, { FunctionComponent } from 'react';
import { Field, Form, Formik } from 'formik';
import Button from '@mui/material/Button';
import * as Yup from 'yup';
import { graphql, useMutation } from 'react-relay';
import makeStyles from '@mui/styles/makeStyles';
import { RecordSourceSelectorProxy } from 'relay-runtime';
import { FormikConfig } from 'formik/dist/types';
import Drawer, { DrawerVariant } from '@components/common/drawer/Drawer';
import { useFormatter } from '../../../../components/i18n';
import { handleErrorInForm } from '../../../../relay/environment';
import TextField from '../../../../components/TextField';
import KillChainPhasesField from '../../common/form/KillChainPhasesField';
import CreatedByField from '../../common/form/CreatedByField';
import ObjectLabelField from '../../common/form/ObjectLabelField';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';
import MarkdownField from '../../../../components/MarkdownField';
import { ExternalReferencesField } from '../../common/form/ExternalReferencesField';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import { useSchemaCreationValidation } from '../../../../utils/hooks/useEntitySettings';
import { insertNode } from '../../../../utils/store';
import { Theme } from '../../../../components/Theme';
import { Option } from '../../common/form/ReferenceField';
import { AttackPatternCreationMutation, AttackPatternCreationMutation$variables } from './__generated__/AttackPatternCreationMutation.graphql';
import { AttackPatternsLinesPaginationQuery$variables } from './__generated__/AttackPatternsLinesPaginationQuery.graphql';
import useDefaultValues from '../../../../utils/hooks/useDefaultValues';
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

const attackPatternMutation = graphql`
  mutation AttackPatternCreationMutation($input: AttackPatternAddInput!) {
    attackPatternAdd(input: $input) {
      id
      standard_id
      name
      entity_type
      parent_types
      description
      isSubAttackPattern
      x_mitre_id
      objectMarking {
        edges {
          node {
            id
            definition_type
            definition
            x_opencti_order
            x_opencti_color
          }
        }
      }
      objectLabel {
        edges {
          node {
            id
            value
            color
          }
        }
      }
      subAttackPatterns {
        edges {
          node {
            id
            name
            description
            x_mitre_id
          }
        }
      }
    }
  }
`;

const ATTACK_PATTERN_TYPE = 'Attack-Pattern';

interface AttackPatternAddInput {
  name: string
  description: string
  x_mitre_id: string
  confidence: number | undefined
  createdBy: Option | undefined
  objectMarking: Option[]
  killChainPhases: Option[]
  objectLabel: Option[]
  externalReferences: { value: string }[]
  file: File | undefined
}

interface AttackPatternFormProps {
  updater: (store: RecordSourceSelectorProxy, key: string) => void;
  onReset?: () => void;
  onCompleted?: () => void;
  defaultCreatedBy?: { value: string; label: string };
  defaultMarkingDefinitions?: { value: string; label: string }[];
  defaultConfidence?: number;
  inputValue?: string;
}

export const AttackPatternCreationForm: FunctionComponent<AttackPatternFormProps> = ({
  updater,
  onReset,
  onCompleted,
  defaultCreatedBy,
  defaultMarkingDefinitions,
}) => {
  const classes = useStyles();
  const { t } = useFormatter();
  const basicShape = {
    name: Yup.string().min(2).required(t('This field is required')),
    description: Yup.string().nullable(),
    x_mitre_id: Yup.string().nullable(),
  };
  const attackPatternValidator = useSchemaCreationValidation(
    ATTACK_PATTERN_TYPE,
    basicShape,
  );

  const [commit] = useMutation<AttackPatternCreationMutation>(
    attackPatternMutation,
  );

  const onSubmit: FormikConfig<AttackPatternAddInput>['onSubmit'] = (
    values,
    {
      setSubmitting,
      setErrors,
      resetForm,
    },
  ) => {
    const input: AttackPatternCreationMutation$variables['input'] = {
      name: values.name,
      description: values.description,
      x_mitre_id: values.x_mitre_id,
      confidence: parseInt(String(values.confidence), 10),
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
          updater(store, 'attackPatternAdd');
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
    ATTACK_PATTERN_TYPE,
    {
      name: '',
      x_mitre_id: '',
      description: '',
      confidence: undefined,
      createdBy: defaultCreatedBy,
      objectMarking: defaultMarkingDefinitions ?? [],
      killChainPhases: [],
      objectLabel: [],
      externalReferences: [],
      file: undefined,
    },
  );

  return (
    <Formik
      initialValues={initialValues}
      validationSchema={attackPatternValidator}
      onSubmit={onSubmit}
      onReset={onReset}
    >
      {({ submitForm, handleReset, isSubmitting, setFieldValue, values }) => (
        <Form style={{ margin: '20px 0 20px 0' }}>
          <Field
            component={TextField}
            name="name"
            label={t('Name')}
            fullWidth={true}
            detectDuplicate={['Attack-Pattern']}
          />
          <Field
            component={TextField}
            name="x_mitre_id"
            label={t('External ID')}
            fullWidth={true}
            style={{ marginTop: 20 }}
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
          </div>
        </Form>
      )}
    </Formik>
  );
};

const AttackPatternCreation = ({
  paginationOptions,
}: {
  paginationOptions: AttackPatternsLinesPaginationQuery$variables;
}) => {
  const { t } = useFormatter();
  const updater = (store: RecordSourceSelectorProxy) => insertNode(
    store,
    'Pagination_attackPatterns',
    paginationOptions,
    'attackPatternAdd',
  );

  return (
    <Drawer
      title={t('Create an attack pattern')}
      variant={DrawerVariant.create}
    >
      {({ onClose }) => (
        <AttackPatternCreationForm
          updater={updater}
          onCompleted={onClose}
          onReset={onClose}
        />
      )}
    </Drawer>
  );
};

export default AttackPatternCreation;
