import React, { FunctionComponent, useState } from 'react';
import { Field, Form, Formik } from 'formik';
import Button from '@mui/material/Button';
import * as Yup from 'yup';
import { graphql } from 'react-relay';
import makeStyles from '@mui/styles/makeStyles';
import { RecordSourceSelectorProxy } from 'relay-runtime';
import { FormikConfig } from 'formik/dist/types';
import Drawer, { DrawerControlledDialProps, DrawerVariant } from '@components/common/drawer/Drawer';
import ConfidenceField from '@components/common/form/ConfidenceField';
import useHelper from 'src/utils/hooks/useHelper';
import { Dialog, DialogContent, DialogTitle, Fab } from '@mui/material';
import { Add } from '@mui/icons-material';
import { useFormatter } from '../../../../components/i18n';
import { handleErrorInForm } from '../../../../relay/environment';
import TextField from '../../../../components/TextField';
import KillChainPhasesField from '../../common/form/KillChainPhasesField';
import CreatedByField from '../../common/form/CreatedByField';
import ObjectLabelField from '../../common/form/ObjectLabelField';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';
import MarkdownField from '../../../../components/fields/MarkdownField';
import { ExternalReferencesField } from '../../common/form/ExternalReferencesField';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import { useSchemaCreationValidation } from '../../../../utils/hooks/useEntitySettings';
import { insertNode } from '../../../../utils/store';
import type { Theme } from '../../../../components/Theme';
import { Option } from '../../common/form/ReferenceField';
import { AttackPatternCreationMutation, AttackPatternCreationMutation$variables } from './__generated__/AttackPatternCreationMutation.graphql';
import { AttackPatternsLinesPaginationQuery$variables } from './__generated__/AttackPatternsLinesPaginationQuery.graphql';
import useDefaultValues from '../../../../utils/hooks/useDefaultValues';
import CustomFileUploader from '../../common/files/CustomFileUploader';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
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
        id
        definition_type
        definition
        x_opencti_order
        x_opencti_color
      }
      objectLabel {
        id
        value
        color
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
  inputValue,
}) => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const basicShape = {
    name: Yup.string().trim().min(2).required(t_i18n('This field is required')),
    description: Yup.string().nullable(),
    x_mitre_id: Yup.string().nullable(),
  };
  const attackPatternValidator = useSchemaCreationValidation(
    ATTACK_PATTERN_TYPE,
    basicShape,
  );

  const [commit] = useApiMutation<AttackPatternCreationMutation>(
    attackPatternMutation,
    undefined,
    { successMessage: `${t_i18n('entity_Attack-Pattern')} ${t_i18n('successfully created')}` },
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
      name: inputValue ?? '',
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
            label={t_i18n('Name')}
            fullWidth={true}
            detectDuplicate={['Attack-Pattern']}
          />
          <Field
            component={TextField}
            name="x_mitre_id"
            label={t_i18n('External ID')}
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
          <ConfidenceField
            entityType="Attack-Pattern"
            containerStyle={fieldSpacingContainerStyle}
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
          </div>
        </Form>
      )}
    </Formik>
  );
};

const AttackPatternCreation = ({
  contextual,
  display,
  inputValue,
  paginationOptions,
}: {
  contextual?: boolean;
  display?: boolean;
  inputValue?: string;
  paginationOptions: AttackPatternsLinesPaginationQuery$variables;
}) => {
  const { t_i18n } = useFormatter();
  const { isFeatureEnable } = useHelper();
  const isFABReplaced = isFeatureEnable('FAB_REPLACEMENT');
  const [open, setOpen] = useState<boolean>(false);
  const handleOpen = () => setOpen(true);
  const handleClose = () => setOpen(false);
  const updater = (store: RecordSourceSelectorProxy) => insertNode(
    store,
    'Pagination_attackPatterns',
    paginationOptions,
    'attackPatternAdd',
  );
  const CreateAttackPatternControlledDial = (props: DrawerControlledDialProps) => (
    <CreateEntityControlledDial entityType='Attack-Pattern' {...props} />
  );
  const CreateAttackPatternControlledDialContextual = CreateAttackPatternControlledDial({
    onOpen: handleOpen,
    onClose: () => {},
  });
  const renderClassic = () => (
    <Drawer
      title={t_i18n('Create an attack pattern')}
      variant={isFABReplaced ? undefined : DrawerVariant.create}
      controlledDial={isFABReplaced ? CreateAttackPatternControlledDial : undefined}
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

  const renderContextual = () => (
    <div style={{
      display: display ? 'block' : 'none',
    }}
    >
      {isFABReplaced
        ? (
          <div style={{ marginTop: '5px' }}>
            {CreateAttackPatternControlledDialContextual}
          </div>
        ) : (
          <Fab
            onClick={handleOpen}
            color="secondary"
            aria-label="Add"
            style={{
              position: 'fixed',
              bottom: 30,
              right: 30,
              zIndex: 2000,
            }}
          >
            <Add />
          </Fab>
        )
      }
      <Dialog open={open} onClose={handleClose} PaperProps={{ elevation: 1 }}>
        <DialogTitle>{t_i18n('Create an attack pattern')}</DialogTitle>
        <DialogContent>
          <AttackPatternCreationForm
            inputValue={inputValue}
            updater={updater}
            onCompleted={handleClose}
            onReset={handleClose}
          />
        </DialogContent>
      </Dialog>
    </div>
  );

  return contextual
    ? renderContextual()
    : renderClassic();
};

export default AttackPatternCreation;
