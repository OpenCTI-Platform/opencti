import React, { FunctionComponent, useRef, useState } from 'react';
import { graphql, PreloadedQuery } from 'react-relay';
import Typography from '@mui/material/Typography';
import { FormikConfig } from 'formik/dist/types';
import makeStyles from '@mui/styles/makeStyles';
import * as Yup from 'yup';
import IconButton from '@mui/material/IconButton';
import { EditOutlined, ExpandLessOutlined, ExpandMoreOutlined, RateReviewOutlined } from '@mui/icons-material';
import Accordion from '@mui/material/Accordion';
import AccordionSummary from '@mui/material/AccordionSummary';
import AccordionDetails from '@mui/material/AccordionDetails';
import { Field, Form, Formik } from 'formik';
import Button from '@mui/material/Button';
import useHelper from 'src/utils/hooks/useHelper';
import { NOTE_TYPE, noteCreationUserMutation } from './NoteCreation';
import { insertNode } from '../../../../utils/store';
import usePreloadedFragment from '../../../../utils/hooks/usePreloadedFragment';
import type { Theme } from '../../../../components/Theme';
import { Option } from '../../common/form/ReferenceField';
import { useFormatter } from '../../../../components/i18n';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNPARTICIPATE } from '../../../../utils/hooks/useGranted';
import AddNotes from './AddNotes';
import StixCoreObjectOrStixCoreRelationshipNoteCard from './StixCoreObjectOrStixCoreRelationshipNoteCard';
import TextField from '../../../../components/TextField';
import MarkdownField from '../../../../components/fields/MarkdownField';
import OpenVocabField from '../../common/form/OpenVocabField';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import ConfidenceField from '../../common/form/ConfidenceField';
import ObjectLabelField from '../../common/form/ObjectLabelField';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';
import {
  StixCoreObjectOrStixCoreRelationshipNotesCardsQuery,
  StixCoreObjectOrStixCoreRelationshipNotesCardsQuery$variables,
} from './__generated__/StixCoreObjectOrStixCoreRelationshipNotesCardsQuery.graphql';
import { StixCoreObjectOrStixCoreRelationshipNotesCards_data$key } from './__generated__/StixCoreObjectOrStixCoreRelationshipNotesCards_data.graphql';
import SliderField from '../../../../components/fields/SliderField';
import { useSchemaCreationValidation } from '../../../../utils/hooks/useEntitySettings';
import useDefaultValues from '../../../../utils/hooks/useDefaultValues';
import { convertMarking } from '../../../../utils/edition';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import AddNotesFunctionalComponent from './AddNotesFunctionalComponent';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles<Theme>((theme) => ({
  heading: {
    display: 'flex',
  },
  buttons: {
    margin: '20px 0 5px 0',
  },
  buttonMore: {
    float: 'left',
  },
  buttonAction: {
    float: 'right',
    marginLeft: theme.spacing(2),
  },
  createButton: {
    float: 'left',
    marginTop: -15,
  },
}));

export const stixCoreObjectOrStixCoreRelationshipNotesCardsQuery = graphql`
  query StixCoreObjectOrStixCoreRelationshipNotesCardsQuery(
    $count: Int!
    $orderBy: NotesOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
  ) {
    ...StixCoreObjectOrStixCoreRelationshipNotesCards_data
      @arguments(
        count: $count
        orderBy: $orderBy
        orderMode: $orderMode
        filters: $filters
      )
  }
`;

const stixCoreObjectOrStixCoreRelationshipNotesCardsFragment = graphql`
  fragment StixCoreObjectOrStixCoreRelationshipNotesCards_data on Query
  @argumentDefinitions(
    count: { type: "Int", defaultValue: 25 }
    orderBy: { type: "NotesOrdering" }
    orderMode: { type: "OrderingMode" }
    filters: { type: "FilterGroup" }
  ) {
    notes(
      first: $count
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    ) @connection(key: "Pagination_notes") {
      edges {
        node {
          id
          ...StixCoreObjectOrStixCoreRelationshipNoteCard_node
          objectMarking {
            id
            definition_type
            definition
            x_opencti_order
            x_opencti_color
          }
        }
      }
    }
  }
`;

const toFinalValues = (values: NoteAddInput, id: string) => {
  return {
    attribute_abstract: values.attribute_abstract,
    content: values.content,
    confidence: parseInt(String(values.confidence), 10),
    note_types: values.note_types,
    likelihood: parseInt(String(values.likelihood), 10),
    objectMarking: values.objectMarking.map((v) => v.value),
    objectLabel: values.objectLabel.map((v) => v.value),
    objects: [id],
  };
};

const toOptions = (
  objectMarkings: readonly DefaultMarking[] | undefined = [],
) => (objectMarkings ?? []).map(convertMarking);

export interface NoteAddInput {
  attribute_abstract: string;
  content: string;
  confidence: number | undefined;
  note_types: string[];
  likelihood?: number;
  objectMarking: Option[];
  objectLabel: Option[];
}

interface DefaultMarking {
  readonly definition: string | null | undefined;
  readonly definition_type: string | null | undefined;
  readonly id: string;
  readonly x_opencti_color: string | null | undefined;
  readonly x_opencti_order?: number;
}

interface StixCoreObjectOrStixCoreRelationshipNotesCardsProps {
  id: string;
  marginTop?: number;
  queryRef: PreloadedQuery<StixCoreObjectOrStixCoreRelationshipNotesCardsQuery>;
  paginationOptions: StixCoreObjectOrStixCoreRelationshipNotesCardsQuery$variables;
  readonly defaultMarkings?: readonly DefaultMarking[]
  title: string;
}

const StixCoreObjectOrStixCoreRelationshipNotesCards: FunctionComponent<
StixCoreObjectOrStixCoreRelationshipNotesCardsProps
> = ({
  id,
  marginTop,
  queryRef,
  paginationOptions,
  defaultMarkings,
  title,
}) => {
  const { t_i18n } = useFormatter();
  const { isFeatureEnable } = useHelper();
  const isFABReplaced = isFeatureEnable('FAB_REPLACEMENT');
  const classes = useStyles();
  const basicShape = {
    content: Yup.string().trim().min(2).required(t_i18n('This field is required')),
    attribute_abstract: Yup.string().nullable(),
    confidence: Yup.number(),
    note_types: Yup.array(),
    likelihood: Yup.number().min(0).max(100),
  };
  // created & createdBy must be excluded from the validation, it will be handled directly by the backend
  const noteValidator = useSchemaCreationValidation('Note', basicShape, [
    'created',
    'createdBy',
  ]);
  const data = usePreloadedFragment<
  StixCoreObjectOrStixCoreRelationshipNotesCardsQuery,
  StixCoreObjectOrStixCoreRelationshipNotesCards_data$key
  >({
    queryDef: stixCoreObjectOrStixCoreRelationshipNotesCardsQuery,
    fragmentDef: stixCoreObjectOrStixCoreRelationshipNotesCardsFragment,
    queryRef,
  });
  const notes = data?.notes?.edges ?? [];
  const bottomRef = useRef<HTMLDivElement>(null);
  const [open, setOpen] = useState<boolean>(false);

  const [more, setMore] = useState<boolean>(false);
  const initialValues = useDefaultValues<NoteAddInput>(NOTE_TYPE, {
    attribute_abstract: '',
    content: '',
    likelihood: 50,
    confidence: undefined,
    note_types: [],
    objectMarking: toOptions(defaultMarkings),
    objectLabel: [],
  });
  const scrollToBottom = () => {
    setTimeout(() => {
      bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
    }, 300);
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
  const handleToggleMore = () => {
    setMore(!more);
  };
  const [commit] = useApiMutation(noteCreationUserMutation);
  const onSubmit: FormikConfig<NoteAddInput>['onSubmit'] = (
    values,
    { setSubmitting, resetForm },
  ) => {
    const finalValues = toFinalValues(values, id);
    commit({
      variables: {
        input: finalValues,
      },
      updater: (store) => {
        insertNode(store, 'Pagination_notes', paginationOptions, 'userNoteAdd');
      },
      onCompleted: () => {
        setSubmitting(false);
        resetForm();
      },
    });
  };
  return (
    <div style={{ marginTop: marginTop || 55 }}>
      <Typography variant="h4" gutterBottom={true} style={{ float: 'left' }}>
        {title}
      </Typography>
      <Security needs={[KNOWLEDGE_KNPARTICIPATE]}>
        <>
          <IconButton
            color="primary"
            onClick={handleToggleWrite}
            classes={{ root: classes.createButton }}
            size="large"
          >
            <EditOutlined fontSize="small" />
          </IconButton>
          {isFABReplaced
            ? <AddNotesFunctionalComponent
                stixCoreObjectOrStixCoreRelationshipId={id}
                stixCoreObjectOrStixCoreRelationshipNotes={data}
                paginationOptions={paginationOptions}
              />
            : <AddNotes
                stixCoreObjectOrStixCoreRelationshipId={id}
                stixCoreObjectOrStixCoreRelationshipNotes={notes}
                paginationOptions={paginationOptions}
              />
          }
        </>
      </Security>
      <div className="clearfix" />
      {notes
        .map(({ node }) => node)
        .map((note) => {
          return (
            <StixCoreObjectOrStixCoreRelationshipNoteCard
              key={note.id}
              data={note}
              stixCoreObjectOrStixCoreRelationshipId={id}
              paginationOptions={paginationOptions}
            />
          );
        })}
      <Security needs={[KNOWLEDGE_KNPARTICIPATE]}>
        <Accordion
          style={{ margin: `${notes.length > 0 ? '30' : '0'}px 0 80px 0` }}
          expanded={open}
          variant="outlined"
        >
          <AccordionSummary
            expandIcon={<ExpandMoreOutlined />}
            onClick={handleToggleWrite}
          >
            <Typography className={classes.heading}>
              <RateReviewOutlined />
              &nbsp;&nbsp;&nbsp;&nbsp;
              <span style={{ fontWeight: 500 }}>{t_i18n('Write a note')}</span>
            </Typography>
          </AccordionSummary>
          <AccordionDetails style={{ width: '100%' }}>
            <Formik<NoteAddInput>
              initialValues={initialValues}
              validationSchema={noteValidator}
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
                    component={MarkdownField}
                    name="content"
                    label={t_i18n('Content')}
                    fullWidth={true}
                    multiline={true}
                    rows="4"
                  />
                  <ObjectMarkingField
                    name="objectMarking"
                    style={fieldSpacingContainerStyle}
                    setFieldValue={setFieldValue}
                  />
                  {more && (
                    <>
                      <Field
                        component={TextField}
                        name="attribute_abstract"
                        label={t_i18n('Abstract')}
                        fullWidth={true}
                        style={{ marginTop: 20 }}
                      />
                      <OpenVocabField
                        label={t_i18n('Note types')}
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
                        label={t_i18n('Likelihood')}
                        fullWidth={true}
                        style={{ marginTop: 20 }}
                      />
                      <ObjectLabelField
                        name="objectLabel"
                        style={{ marginTop: 10, width: '100%' }}
                        setFieldValue={setFieldValue}
                        values={values.objectLabel}
                      />
                    </>
                  )}
                  <div className={classes.buttons}>
                    <Button
                      variant="contained"
                      color="secondary"
                      onClick={submitForm}
                      disabled={isSubmitting}
                      classes={{ root: classes.buttonAction }}
                      size="small"
                    >
                      {t_i18n('Create')}
                    </Button>
                    <Button
                      variant="contained"
                      onClick={handleToggleMore}
                      disabled={isSubmitting}
                      classes={{ root: classes.buttonMore }}
                      size="small"
                      endIcon={
                        more ? <ExpandLessOutlined /> : <ExpandMoreOutlined />
                      }
                    >
                      {more ? t_i18n('Less fields') : t_i18n('More fields')}
                    </Button>
                    <Button
                      variant="contained"
                      onClick={handleReset}
                      disabled={isSubmitting}
                      classes={{ root: classes.buttonAction }}
                      size="small"
                    >
                      {t_i18n('Cancel')}
                    </Button>
                    <div className="clearfix" />
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
