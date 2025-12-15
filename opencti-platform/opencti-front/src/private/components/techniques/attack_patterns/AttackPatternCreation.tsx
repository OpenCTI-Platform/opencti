import React, { FunctionComponent, useState } from 'react';
import { Field, Form, Formik } from 'formik';
import Button from '@common/button/Button';
import * as Yup from 'yup';
import { graphql } from 'react-relay';
import makeStyles from '@mui/styles/makeStyles';
import { RecordSourceSelectorProxy } from 'relay-runtime';
import { FormikConfig } from 'formik/dist/types';
import Drawer, { DrawerControlledDialProps } from '@components/common/drawer/Drawer';
import { AttackPatternsLinesPaginationQuery$variables } from '@components/techniques/__generated__/AttackPatternsLinesPaginationQuery.graphql';
import ConfidenceField from '@components/common/form/ConfidenceField';
import { Dialog, DialogContent, DialogTitle } from '@mui/material';
import { useFormatter } from '../../../../components/i18n';
import { handleErrorInForm } from '../../../../relay/environment';
import TextField from '../../../../components/TextField';
import KillChainPhasesField from '../../common/form/KillChainPhasesField';
import CreatedByField from '../../common/form/CreatedByField';
import ObjectLabelField from '../../common/form/ObjectLabelField';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';
import MarkdownField from '../../../../components/fields/MarkdownField';
import { ExternalReferencesField } from '../../common/form/ExternalReferencesField';
import { FieldOption, fieldSpacingContainerStyle } from '../../../../utils/field';
import { useDynamicSchemaCreationValidation, useIsMandatoryAttribute, yupShapeConditionalRequired } from '../../../../utils/hooks/useEntitySettings';
import { insertNode } from '../../../../utils/store';
import type { Theme } from '../../../../components/Theme';
import { AttackPatternCreationMutation, AttackPatternCreationMutation$variables } from './__generated__/AttackPatternCreationMutation.graphql';
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
      ...AttackPatternsLine_node
      id
      standard_id
      name
      representative {
        main
      }
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
  name: string;
  description: string;
  x_mitre_id: string;
  confidence: number | undefined;
  createdBy: FieldOption | undefined;
  objectMarking: FieldOption[];
  killChainPhases: FieldOption[];
  objectLabel: FieldOption[];
  externalReferences: { value: string }[];
  file: File | undefined;
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
  const { mandatoryAttributes } = useIsMandatoryAttribute(ATTACK_PATTERN_TYPE);
  const basicShape = yupShapeConditionalRequired({
    name: Yup.string().trim().min(2),
    description: Yup.string().nullable(),
    x_mitre_id: Yup.string().nullable(),
  }, mandatoryAttributes);

  const attackPatternValidator = useDynamicSchemaCreationValidation(mandatoryAttributes, basicShape);

  const [commit] = useApiMutation<AttackPatternCreationMutation>(
    attackPatternMutation,
    undefined,
    { successMessage: `${t_i18n('entity_Attack-Pattern')} ${t_i18n('successfully created')}` },
  );

  const onSubmit: FormikConfig<AttackPatternAddInput>['onSubmit'] = (
    values,
    { setSubmitting, setErrors, resetForm },
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
    <Formik<AttackPatternAddInput>
      initialValues={initialValues}
      validationSchema={attackPatternValidator}
      validateOnChange={true}
      validateOnBlur={true}
      onSubmit={onSubmit}
      onReset={onReset}
    >
      {({ submitForm, handleReset, isSubmitting, setFieldValue, values }) => (
        <Form>
          <Field
            component={TextField}
            name="name"
            label={t_i18n('Name')}
            required={(mandatoryAttributes.includes('name'))}
            fullWidth={true}
            detectDuplicate={['Attack-Pattern']}
          />
          <Field
            component={TextField}
            name="x_mitre_id"
            label={t_i18n('External ID')}
            required={(mandatoryAttributes.includes('x_mitre_id'))}
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
          <ConfidenceField
            entityType="Attack-Pattern"
            containerStyle={fieldSpacingContainerStyle}
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
    <CreateEntityControlledDial entityType="Attack-Pattern" {...props} />
  );
  const CreateAttackPatternControlledDialContextual = CreateAttackPatternControlledDial({
    onOpen: handleOpen,
    onClose: () => { },
  });
  const renderClassic = () => (
    <Drawer
      title={t_i18n('Create an attack pattern')}
      controlledDial={CreateAttackPatternControlledDial}
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
      <div style={{ marginTop: '5px' }}>
        {CreateAttackPatternControlledDialContextual}
      </div>
      <Dialog open={open} onClose={handleClose} slotProps={{ paper: { elevation: 1 } }}>
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
