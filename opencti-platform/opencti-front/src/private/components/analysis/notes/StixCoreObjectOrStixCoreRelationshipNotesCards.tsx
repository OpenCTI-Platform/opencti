import React, { FunctionComponent, useRef, useState } from 'react';
import { graphql, PreloadedQuery, useMutation } from 'react-relay';
import Typography from '@mui/material/Typography';
import { FormikConfig } from 'formik/dist/types';
import makeStyles from '@mui/styles/makeStyles';
import * as Yup from 'yup';
import IconButton from '@mui/material/IconButton';
import { EditOutlined, ExpandMoreOutlined, RateReviewOutlined } from '@mui/icons-material';
import Accordion from '@mui/material/Accordion';
import AccordionSummary from '@mui/material/AccordionSummary';
import AccordionDetails from '@mui/material/AccordionDetails';
import { Field, Form, Formik } from 'formik';
import Button from '@mui/material/Button';
import { noteCreationUserMutation } from './NoteCreation';
import { insertNode } from '../../../../utils/store';
import usePreloadedFragment from '../../../../utils/hooks/usePreloadedFragment';
import { Theme } from '../../../../components/Theme';
import { Option } from '../../common/form/ReferenceField';
import { useFormatter } from '../../../../components/i18n';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNPARTICIPATE } from '../../../../utils/hooks/useGranted';
import AddNotes from './AddNotes';
import StixCoreObjectOrStixCoreRelationshipNoteCard from './StixCoreObjectOrStixCoreRelationshipNoteCard';
import TextField from '../../../../components/TextField';
import MarkDownField from '../../../../components/MarkDownField';
import OpenVocabField from '../../common/form/OpenVocabField';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import ConfidenceField from '../../common/form/ConfidenceField';
import ObjectLabelField from '../../common/form/ObjectLabelField';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';
import {
  StixCoreObjectOrStixCoreRelationshipNotesCardsQuery, StixCoreObjectOrStixCoreRelationshipNotesCardsQuery$variables,
} from './__generated__/StixCoreObjectOrStixCoreRelationshipNotesCardsQuery.graphql';
import {
  StixCoreObjectOrStixCoreRelationshipNotesCards_data$key,
} from './__generated__/StixCoreObjectOrStixCoreRelationshipNotesCards_data.graphql';

const useStyles = makeStyles<Theme>((theme) => ({
  paper: {
    margin: 0,
    padding: '20px 20px 20px 20px',
    borderRadius: 6,
  },
  heading: {
    display: 'flex',
  },
  buttons: {
    marginTop: 20,
    textAlign: 'right',
  },
  button: {
    marginLeft: theme.spacing(2),
  },
  createButton: {
    float: 'left',
    marginTop: -15,
  },
}));

export const stixCoreObjectOrStixCoreRelationshipNotesCardsQuery = graphql`
  query StixCoreObjectOrStixCoreRelationshipNotesCardsQuery($count: Int!, $filters: [NotesFiltering!]) {
    ...StixCoreObjectOrStixCoreRelationshipNotesCards_data @arguments(count: $count, filters: $filters)
  }
`;

const stixCoreObjectOrStixCoreRelationshipNotesCardsFragment = graphql`
  fragment StixCoreObjectOrStixCoreRelationshipNotesCards_data on Query
  @argumentDefinitions(count: { type: "Int", defaultValue: 25 }, filters: { type: "[NotesFiltering!]" }) {
    notes(first: $count, filters: $filters)
    @connection(key: "Pagination_notes") {
      edges {
        node {
          id
          ...StixCoreObjectOrStixCoreRelationshipNoteCard_node
        }
      }
    }
  }
`;

const noteValidation = (t: (message: string) => string) => Yup.object().shape({
  attribute_abstract: Yup.string().nullable(),
  content: Yup.string().required(t('This field is required')),
  confidence: Yup.number(),
  note_types: Yup.array(),
  likelihood: Yup.number().min(0).max(100),
});

const toFinalValues = (values: NoteAddInput, id: string) => {
  return {
    attribute_abstract: values.attribute_abstract,
    content: values.content,
    confidence: () => parseInt(String(values.confidence), 10),
    note_types: values.note_types,
    likelihood: () => parseInt(String(values.likelihood), 10),
    objectMarking: values.objectMarking.map((v) => v.value),
    objectLabel: values.objectLabel.map((v) => v.value),
    objects: [id],
  };
};

const toOptions = (objectMarkings: { id: string, definition: string | null }[]) => objectMarkings.map((objectMarking) => ({
  label: objectMarking.definition ?? objectMarking.id,
  value: objectMarking.id,
}));

export interface NoteAddInput {
  attribute_abstract: string,
  content: string,
  confidence: number,
  note_types: string[],
  likelihood?: number
  objectMarking: Option[],
  objectLabel: Option[],
}

interface StixCoreObjectOrStixCoreRelationshipNotesCardsProps {
  id: string,
  marginTop?: number,
  queryRef: PreloadedQuery<StixCoreObjectOrStixCoreRelationshipNotesCardsQuery>,
  paginationOptions: StixCoreObjectOrStixCoreRelationshipNotesCardsQuery$variables,
  defaultMarking: { id: string, definition: string | null }[],
  title: string
}

const StixCoreObjectOrStixCoreRelationshipNotesCards: FunctionComponent<StixCoreObjectOrStixCoreRelationshipNotesCardsProps> = ({
  id,
  marginTop,
  queryRef,
  paginationOptions,
  defaultMarking,
  title,
}) => {
  const { t } = useFormatter();
  const classes = useStyles();

  const data = usePreloadedFragment<StixCoreObjectOrStixCoreRelationshipNotesCardsQuery, StixCoreObjectOrStixCoreRelationshipNotesCards_data$key>({
    linesQuery: stixCoreObjectOrStixCoreRelationshipNotesCardsQuery,
    linesFragment: stixCoreObjectOrStixCoreRelationshipNotesCardsFragment,
    queryRef,
  });

  const notes = data?.notes?.edges ?? [];

  const bottomRef = useRef<HTMLDivElement>(null);
  const [open, setOpen] = useState<boolean>(false);
  const initialValues: NoteAddInput = {
    attribute_abstract: '',
    content: '',
    confidence: 75,
    note_types: [],
    objectMarking: toOptions(defaultMarking),
    objectLabel: [],
  };

  const scrollToBottom = () => {
    setTimeout(() => {
      bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
    }, 400);
  };
  const handleToggleWrite = () => {
    setOpen((oldValue) => {
      const newValue = !oldValue;
      if (newValue) {
        scrollToBottom();
      }
      return newValue;
    });
  };

  const [commit] = useMutation(noteCreationUserMutation);

  const onSubmit: FormikConfig<NoteAddInput>['onSubmit'] = (values, { setSubmitting, resetForm }) => {
    const finalValues = toFinalValues(values, id);

    commit({
      variables: {
        input: finalValues,
      },
      updater: (store) => {
        insertNode(
          store,
          'Pagination_notes',
          paginationOptions,
          'userNoteAdd',
        );
      },
      onCompleted: () => {
        setSubmitting(false);
        resetForm();
      },
    });
  };

  return (
    <div style={{ marginTop: marginTop || 40 }}>
      <Typography variant="h4" gutterBottom={true} style={{ float: 'left' }}>
        {title}
      </Typography>
      <Security needs={[KNOWLEDGE_KNPARTICIPATE]}>
        <>
          <IconButton
            color="secondary"
            onClick={handleToggleWrite}
            classes={{ root: classes.createButton }}
            size="large">
            <EditOutlined fontSize="small" />
          </IconButton>
          <AddNotes
            stixCoreObjectOrStixCoreRelationshipId={id}
            stixCoreObjectOrStixCoreRelationshipNotes={notes}
          />
        </>
      </Security>
      <div className="clearfix" />
      {
        notes.map(({ node }) => node)
          .map((note) => {
            return (
              <StixCoreObjectOrStixCoreRelationshipNoteCard
                key={note.id}
                data={note}
                stixCoreObjectOrStixCoreRelationshipId={id}
                paginationOptions={paginationOptions}
              />
            );
          })
      }
      <Security needs={[KNOWLEDGE_KNPARTICIPATE]}>
        <Accordion
          style={{ margin: `${notes.length > 0 ? '30' : '0'}px 0 30px 0` }}
          expanded={open}
          variant="outlined">
          <AccordionSummary
            expandIcon={<ExpandMoreOutlined />}
            onClick={handleToggleWrite}>
            <Typography className={classes.heading}>
              <RateReviewOutlined />
              &nbsp;&nbsp;&nbsp;&nbsp;
              <span style={{ fontWeight: 500 }}>{t('Write a note')}</span>
            </Typography>
          </AccordionSummary>
          <AccordionDetails style={{ width: '100%' }}>
            <Formik
              initialValues={initialValues}
              validationSchema={noteValidation(t)}
              onSubmit={onSubmit}
              onReset={handleToggleWrite}
            >
              {({
                submitForm,
                handleReset,
                setFieldValue,
                values,
                isSubmitting,
              }) => (
                <Form style={{ width: '100%' }}>
                  <Field
                    component={TextField}
                    variant="standard"
                    name="attribute_abstract"
                    label={t('Abstract')}
                    fullWidth={true}
                  />
                  <Field
                    component={MarkDownField}
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
                    name="confidence"
                    label={t('Confidence')}
                    fullWidth={true}
                    containerStyle={fieldSpacingContainerStyle}
                  />
                  <Field
                    component={TextField}
                    variant="standard"
                    name="likelihood"
                    label={t('Likelihood')}
                    fullWidth={true}
                    style={{ marginTop: 20 }}
                  />
                  <ObjectLabelField
                    name="objectLabel"
                    style={{ marginTop: 20, width: '100%' }}
                    setFieldValue={setFieldValue}
                    values={values.objectLabel}
                  />
                  <ObjectMarkingField
                    name="objectMarking"
                    style={{ marginTop: 20, width: '100%' }}
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
                  </div>
                </Form>
              )}
            </Formik>
          </AccordionDetails>
        </Accordion>
      </Security>
      <div ref={bottomRef} />
    </div>
  );
};

export default StixCoreObjectOrStixCoreRelationshipNotesCards;
