import React, { FunctionComponent, useState } from 'react';
import { Field, Form, Formik } from 'formik';
import * as Yup from 'yup';
import { graphql, useMutation } from 'react-relay';
import Drawer, { DrawerVariant } from '@components/common/drawer/Drawer';
import Dialog from '@mui/material/Dialog';
import DialogContent from '@mui/material/DialogContent';
import DialogTitle from '@mui/material/DialogTitle';
import Button from '@mui/material/Button';
import Fab from '@mui/material/Fab';
import { Add } from '@mui/icons-material';
import makeStyles from '@mui/styles/makeStyles';
import { FormikConfig } from 'formik/dist/types';
import { RecordSourceSelectorProxy } from 'relay-runtime';
import { SimpleFileUpload } from 'formik-mui';
import { useFormatter } from '../../../../components/i18n';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';
import CreatedByField from '../../common/form/CreatedByField';
import ObjectLabelField from '../../common/form/ObjectLabelField';
import MarkdownField from '../../../../components/MarkdownField';
import ConfidenceField from '../../common/form/ConfidenceField';
import TextField from '../../../../components/TextField';
import DateTimePickerField from '../../../../components/DateTimePickerField';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import useGranted, {
  KNOWLEDGE_KNUPDATE,
} from '../../../../utils/hooks/useGranted';
import OpenVocabField from '../../common/form/OpenVocabField';
import { Theme } from '../../../../components/Theme';
import { insertNode } from '../../../../utils/store';
import { Option } from '../../common/form/ReferenceField';
import { NotesLinesPaginationQuery$variables } from './__generated__/NotesLinesPaginationQuery.graphql';
import SliderField from '../../../../components/SliderField';
import { ExternalReferencesField } from '../../common/form/ExternalReferencesField';
import { useSchemaCreationValidation } from '../../../../utils/hooks/useEntitySettings';
import { NoteCreationMutation$variables } from './__generated__/NoteCreationMutation.graphql';
import useDefaultValues from '../../../../utils/hooks/useDefaultValues';

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
      standard_id
      entity_type
      parent_types
      attribute_abstract
      content
      ...NoteLine_node
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
      ...NoteLine_node
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
  createdBy: Option | undefined;
  objectMarking: Option[];
  objectLabel: Option[];
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
  defaultCreatedBy?: Option;
  defaultMarkingDefinitions?: Option[];
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
  const { t } = useFormatter();
  const userIsKnowledgeEditor = useGranted([KNOWLEDGE_KNUPDATE]);
  const basicShape = {
    created: Yup.date()
      .typeError(t('The value must be a datetime (yyyy-MM-dd hh:mm (a|p)m)'))
      .required(t('This field is required')),
    attribute_abstract: Yup.string().nullable(),
    content: Yup.string().min(2).required(t('This field is required')),
    confidence: Yup.number().nullable(),
    note_types: Yup.array().nullable(),
    likelihood: Yup.number().min(0).max(100),
  };
  // createdBy must be excluded from the validation if user is not an editor, it will be handled directly by the backend
  const noteValidator = useSchemaCreationValidation(
    NOTE_TYPE,
    basicShape,
    userIsKnowledgeEditor ? [] : ['createdBy'],
  );

  const [commit] = userIsKnowledgeEditor
    ? useMutation(noteCreationMutation)
    : useMutation(noteCreationUserMutation);
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
    content: inputValue || '',
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
      onSubmit={onSubmit}
      onReset={onClose}
    >
      {({ submitForm, handleReset, isSubmitting, setFieldValue, values }) => (
        <Form style={{ margin: '20px 0 20px 0' }}>
          <Field
            component={DateTimePickerField}
            name="created"
            TextFieldProps={{
              label: t('Publication date'),
              variant: 'standard',
              fullWidth: true,
            }}
          />
          <Field
            component={TextField}
            name="attribute_abstract"
            label={t('Abstract')}
            fullWidth={true}
            style={{ marginTop: 20 }}
          />
          <Field
            component={MarkdownField}
            name="content"
            label={t('Content')}
            fullWidth={true}
            multiline={true}
            rows="4"
            style={{ marginTop: 20 }}
          />
          <OpenVocabField
            label={t('Note types')}
            type="note_types_ov"
            name="note_types"
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
            label={t('Likelihood')}
            fullWidth={true}
            style={{ marginTop: 20 }}
          />
          {userIsKnowledgeEditor && (
            <CreatedByField
              name="createdBy"
              style={{ marginTop: 10 }}
              setFieldValue={setFieldValue}
            />
          )}
          <ObjectLabelField
            name="objectLabel"
            style={{ marginTop: userIsKnowledgeEditor ? 20 : 10 }}
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
                    <CustomFileUpload setFieldValue={setFieldValue} />
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

const NoteCreation: FunctionComponent<NoteCreationProps> = ({
  inputValue,
  display,
  contextual,
  paginationOptions,
}) => {
  const { t } = useFormatter();
  const classes = useStyles();
  const [open, setOpen] = useState(false);
  const updater = (store: RecordSourceSelectorProxy, key: string) => {
    return insertNode(store, 'Pagination_notes', paginationOptions, key);
  };
  const renderClassic = () => {
    return (
      <Drawer
        title={t('Create a note')}
        variant={DrawerVariant.create}
      >
        <NoteCreationForm inputValue={inputValue} updater={updater} />
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
          PaperProps={{ elevation: 1 }}
        >
          <DialogTitle>{t('Create a note')}</DialogTitle>
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
