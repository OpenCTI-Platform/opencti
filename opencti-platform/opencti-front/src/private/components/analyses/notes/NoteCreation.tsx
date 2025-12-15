import React, { FunctionComponent, useState } from 'react';
import { Field, Form, Formik } from 'formik';
import * as Yup from 'yup';
import { graphql } from 'react-relay';
import Drawer, { DrawerControlledDialProps } from '@components/common/drawer/Drawer';
import Dialog from '@mui/material/Dialog';
import DialogContent from '@mui/material/DialogContent';
import DialogTitle from '@mui/material/DialogTitle';
import Button from '@common/button/Button';
import Fab from '@mui/material/Fab';
import { Add } from '@mui/icons-material';
import makeStyles from '@mui/styles/makeStyles';
import { FormikConfig } from 'formik/dist/types';
import { RecordSourceSelectorProxy } from 'relay-runtime';
import { NotesLinesPaginationQuery$variables } from '@components/analyses/__generated__/NotesLinesPaginationQuery.graphql';
import { useFormatter } from '../../../../components/i18n';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';
import CreatedByField from '../../common/form/CreatedByField';
import ObjectLabelField from '../../common/form/ObjectLabelField';
import MarkdownField from '../../../../components/fields/MarkdownField';
import ConfidenceField from '../../common/form/ConfidenceField';
import TextField from '../../../../components/TextField';
import DateTimePickerField from '../../../../components/DateTimePickerField';
import { FieldOption, fieldSpacingContainerStyle } from '../../../../utils/field';
import useGranted, { KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';
import OpenVocabField from '../../common/form/OpenVocabField';
import type { Theme } from '../../../../components/Theme';
import { insertNode } from '../../../../utils/store';
import SliderField from '../../../../components/fields/SliderField';
import { ExternalReferencesField } from '../../common/form/ExternalReferencesField';
import { NoteCreationMutation$variables } from './__generated__/NoteCreationMutation.graphql';
import useDefaultValues from '../../../../utils/hooks/useDefaultValues';
import CustomFileUploader from '../../common/files/CustomFileUploader';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import CreateEntityControlledDial from '../../../../components/CreateEntityControlledDial';
import { useDynamicSchemaCreationValidation, useIsMandatoryAttribute, yupShapeConditionalRequired } from '../../../../utils/hooks/useEntitySettings';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles<Theme>((theme) => ({
  createButtonContextual: {
    position: 'fixed',
    bottom: 30,
    right: 30,
    zIndex: 2000,
  },
  buttons: {
    marginTop: 20,
    textAlign: 'right',
  },
  button: {
    marginLeft: theme.spacing(2),
  },
}));

export const noteCreationUserMutation = graphql`
  mutation NoteCreationUserMutation($input: NoteUserAddInput!) {
    userNoteAdd(input: $input) {
      id
      representative {
        main
      }
      standard_id
      entity_type
      parent_types
      attribute_abstract
      content
      ...NotesLine_node
    }
  }
`;

export const noteCreationMutation = graphql`
  mutation NoteCreationMutation($input: NoteAddInput!) {
    noteAdd(input: $input) {
      id
      standard_id
      entity_type
      parent_types
      attribute_abstract
      content
      ...NotesLine_node
    }
  }
`;

interface NoteAddInput {
  created: Date | null;
  attribute_abstract: string;
  content: string;
  note_types: string[];
  confidence: number | undefined;
  likelihood?: number;
  createdBy: FieldOption | undefined;
  objectMarking: FieldOption[];
  objectLabel: FieldOption[];
  externalReferences: { value: string }[];
  file: File | undefined;
}

interface NoteCreationProps {
  inputValue?: string;
  display?: boolean;
  contextual?: boolean;
  paginationOptions: NotesLinesPaginationQuery$variables;
}

interface NoteFormProps {
  updater: (store: RecordSourceSelectorProxy, key: string) => void;
  onClose?: () => void;
  inputValue?: string;
  defaultCreatedBy?: FieldOption;
  defaultMarkingDefinitions?: FieldOption[];
  defaultConfidence?: number;
}

export const NOTE_TYPE = 'Note';

export const NoteCreationForm: FunctionComponent<NoteFormProps> = ({
  updater,
  onClose,
  inputValue,
  defaultConfidence,
  defaultCreatedBy,
  defaultMarkingDefinitions,
}) => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const userIsKnowledgeEditor = useGranted([KNOWLEDGE_KNUPDATE]);
  const { mandatoryAttributes } = useIsMandatoryAttribute(NOTE_TYPE);
  const basicShape = yupShapeConditionalRequired({
    created: Yup.date()
      .typeError(t_i18n('The value must be a datetime (yyyy-MM-dd hh:mm (a|p)m)')),
    attribute_abstract: Yup.string().nullable(),
    content: Yup.string().trim().min(2),
    confidence: Yup.number().nullable(),
    note_types: Yup.array().nullable(),
    likelihood: Yup.number().min(0).max(100),
    createdBy: Yup.object().nullable(),
    objectLabel: Yup.array().nullable(),
    objectMarking: Yup.array().nullable(),
    externalReferences: Yup.array().nullable(),
    file: Yup.mixed().nullable(),
  }, mandatoryAttributes);
  // createdBy must be excluded from the validation if user is not an editor, it will be handled directly by the backend
  const noteValidator = useDynamicSchemaCreationValidation(
    mandatoryAttributes,
    basicShape,
    userIsKnowledgeEditor ? [] : ['createdBy'],
  );

  const [commit] = useApiMutation(
    userIsKnowledgeEditor
      ? noteCreationMutation
      : noteCreationUserMutation,
    undefined,
    { successMessage: `${t_i18n('entity_Note')} ${t_i18n('successfully created')}` },
  );
  const onSubmit: FormikConfig<NoteAddInput>['onSubmit'] = (
    values,
    { setSubmitting, resetForm },
  ) => {
    const input: NoteCreationMutation$variables['input'] = {
      created: values.created,
      attribute_abstract: values.attribute_abstract,
      content: values.content,
      note_types: values.note_types,
      confidence: parseInt(String(values.confidence), 10),
      likelihood: parseInt(String(values.likelihood), 10),
      createdBy: values.createdBy?.value,
      objectMarking: values.objectMarking.map((v) => v.value),
      objectLabel: values.objectLabel.map((v) => v.value),
      externalReferences: values.externalReferences.map(({ value }) => value),
      file: values.file,
    };
    if (!userIsKnowledgeEditor) {
      delete input.createdBy;
    }
    commit({
      variables: {
        input,
      },
      updater: (store) => {
        if (updater) {
          updater(store, userIsKnowledgeEditor ? 'noteAdd' : 'userNoteAdd');
        }
      },
      onCompleted: () => {
        setSubmitting(false);
        resetForm();
        if (onClose) {
          onClose();
        }
      },
    });
  };

  const initialValues = useDefaultValues<NoteAddInput>(NOTE_TYPE, {
    created: null,
    attribute_abstract: '',
    content: inputValue ?? '',
    note_types: [],
    confidence: defaultConfidence,
    likelihood: 50,
    createdBy: defaultCreatedBy,
    objectMarking: defaultMarkingDefinitions ?? [],
    objectLabel: [],
    externalReferences: [],
    file: undefined,
  });

  return (
    <Formik<NoteAddInput>
      initialValues={initialValues}
      validationSchema={noteValidator}
      validateOnChange={true}
      validateOnBlur={true}
      onSubmit={onSubmit}
      onReset={onClose}
    >
      {({ submitForm, handleReset, isSubmitting, setFieldValue, values }) => (
        <Form>
          <Field
            component={DateTimePickerField}
            name="created"
            textFieldProps={{
              label: t_i18n('Publication date'),
              variant: 'standard',
              fullWidth: true,
              required: mandatoryAttributes.includes('created'),
            }}
          />
          <Field
            component={TextField}
            name="attribute_abstract"
            label={t_i18n('Abstract')}
            required={(mandatoryAttributes.includes('attribute_abstract'))}
            fullWidth={true}
            style={{ marginTop: 20 }}
            askAi={true}
          />
          <Field
            component={MarkdownField}
            name="content"
            label={t_i18n('Content')}
            required={(mandatoryAttributes.includes('content'))}
            fullWidth={true}
            multiline={true}
            rows="4"
            style={{ marginTop: 20 }}
            askAi={true}
          />
          <OpenVocabField
            label={t_i18n('Note types')}
            type="note_types_ov"
            name="note_types"
            required={(mandatoryAttributes.includes('note_types'))}
            onChange={(name, value) => setFieldValue(name, value)}
            containerStyle={fieldSpacingContainerStyle}
            multiple={true}
          />
          <ConfidenceField
            entityType="Note"
            containerStyle={fieldSpacingContainerStyle}
          />
          <Field
            component={SliderField}
            name="likelihood"
            required={(mandatoryAttributes.includes('likelihood'))}
            label={t_i18n('Likelihood')}
            fullWidth={true}
            style={{ marginTop: 20 }}
          />
          {userIsKnowledgeEditor && (
            <CreatedByField
              name="createdBy"
              required={(mandatoryAttributes.includes('createdBy'))}
              style={{ marginTop: 10 }}
              setFieldValue={setFieldValue}
            />
          )}
          <ObjectLabelField
            name="objectLabel"
            required={(mandatoryAttributes.includes('objectLabel'))}
            style={{ marginTop: userIsKnowledgeEditor ? 20 : 10 }}
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

const NoteCreation: FunctionComponent<NoteCreationProps> = ({
  inputValue,
  display,
  contextual,
  paginationOptions,
}) => {
  const { t_i18n } = useFormatter();
  const classes = useStyles();
  const [open, setOpen] = useState(false);
  const updater = (store: RecordSourceSelectorProxy, key: string) => {
    return insertNode(store, 'Pagination_notes', paginationOptions, key);
  };
  const CreateNoteControlledDial = (props: DrawerControlledDialProps) => (
    <CreateEntityControlledDial entityType="Note" {...props} />
  );
  const renderClassic = () => {
    return (
      <Drawer
        title={t_i18n('Create a note')}
        controlledDial={CreateNoteControlledDial}
      >
        <NoteCreationForm
          inputValue={inputValue}
          updater={updater}
        />
      </Drawer>
    );
  };
  const renderContextual = () => {
    return (
      <div style={{ display: display ? 'block' : 'none' }}>
        <Fab
          onClick={() => setOpen(true)}
          color="secondary"
          aria-label="Add"
          className={classes.createButtonContextual}
        >
          <Add />
        </Fab>
        <Dialog
          open={open}
          onClose={() => setOpen(false)}
          slotProps={{ paper: { elevation: 1 } }}
        >
          <DialogTitle>{t_i18n('Create a note')}</DialogTitle>
          <DialogContent>
            <NoteCreationForm
              inputValue={inputValue}
              updater={updater}
              onClose={() => setOpen(false)}
            />
          </DialogContent>
        </Dialog>
      </div>
    );
  };
  if (contextual) {
    return renderContextual();
  }
  return renderClassic();
};

export default NoteCreation;
