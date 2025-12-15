import React, { FunctionComponent, useEffect, useRef, useState } from 'react';
import { graphql, PreloadedQuery } from 'react-relay';
import Typography from '@mui/material/Typography';
import { FormikConfig, FormikHelpers } from 'formik/dist/types';
import * as Yup from 'yup';
import { EditOutlined, ExpandLessOutlined, ExpandMoreOutlined, RateReviewOutlined } from '@mui/icons-material';
import Accordion from '@mui/material/Accordion';
import AccordionSummary from '@mui/material/AccordionSummary';
import AccordionDetails from '@mui/material/AccordionDetails';
import { Field, Formik } from 'formik';
import Button from '@common/button/Button';
import IconButton from '@common/button/IconButton';
import { Stack, Box } from '@mui/material';
import { NOTE_TYPE, noteCreationUserMutation } from './NoteCreation';
import { insertNode } from '../../../../utils/store';
import usePreloadedFragment from '../../../../utils/hooks/usePreloadedFragment';
import { useFormatter } from '../../../../components/i18n';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNPARTICIPATE } from '../../../../utils/hooks/useGranted';
import StixCoreObjectOrStixCoreRelationshipNoteCard from './StixCoreObjectOrStixCoreRelationshipNoteCard';
import TextField from '../../../../components/TextField';
import MarkdownField from '../../../../components/fields/MarkdownField';
import OpenVocabField from '../../common/form/OpenVocabField';
import { FieldOption, fieldSpacingContainerStyle } from '../../../../utils/field';
import ConfidenceField from '../../common/form/ConfidenceField';
import ObjectLabelField from '../../common/form/ObjectLabelField';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';
import {
  StixCoreObjectOrStixCoreRelationshipNotesCardsQuery,
  StixCoreObjectOrStixCoreRelationshipNotesCardsQuery$variables,
} from './__generated__/StixCoreObjectOrStixCoreRelationshipNotesCardsQuery.graphql';
import {
  StixCoreObjectOrStixCoreRelationshipNotesCards_data$data,
  StixCoreObjectOrStixCoreRelationshipNotesCards_data$key,
} from './__generated__/StixCoreObjectOrStixCoreRelationshipNotesCards_data.graphql';
import SliderField from '../../../../components/fields/SliderField';
import useDefaultValues from '../../../../utils/hooks/useDefaultValues';
import { convertMarking } from '../../../../utils/edition';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import AddNotesFunctionalComponent from './AddNotesFunctionalComponent';
import { yupShapeConditionalRequired, useDynamicSchemaCreationValidation, useIsMandatoryAttribute } from '../../../../utils/hooks/useEntitySettings';

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
  objectMarking: FieldOption[];
  objectLabel: FieldOption[];
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
  readonly defaultMarkings?: readonly DefaultMarking[];
  title: string;
}

type HeaderProps = {
  onToggleWrite: () => void;
  id: string;
  data: StixCoreObjectOrStixCoreRelationshipNotesCards_data$data;
} & Pick<StixCoreObjectOrStixCoreRelationshipNotesCardsProps, 'paginationOptions' | 'title'>;

const Header = ({ title, id, data, paginationOptions, onToggleWrite }: HeaderProps) => {
  return (
    <Stack direction="row" flex={1}>
      <Typography variant="h4">{title}</Typography>
      <Security needs={[KNOWLEDGE_KNPARTICIPATE]}>
        <Stack direction="row" justifyContent="space-between" flex={1}>
          <IconButton
            onClick={onToggleWrite}
            sx={{
              marginTop: -0.7,
              marginLeft: 1,
            }}
            variant="tertiary"
            size="small"
          >
            <EditOutlined fontSize="small" />
          </IconButton>

          <AddNotesFunctionalComponent
            stixCoreObjectOrStixCoreRelationshipId={id}
            stixCoreObjectOrStixCoreRelationshipNotes={data}
            paginationOptions={paginationOptions}
          />
        </Stack>
      </Security>
    </Stack>
  );
};

type NoteFormProps = {
  onSubmit: (values: NoteAddInput, formikHelpers: FormikHelpers<NoteAddInput>) => void;
  onToggleWrite: () => void;
  onToggleMore: () => void;
} & Pick<StixCoreObjectOrStixCoreRelationshipNotesCardsProps, 'defaultMarkings'>;

const NoteForm = ({ defaultMarkings, onToggleWrite, onToggleMore, onSubmit }: NoteFormProps) => {
  const { t_i18n } = useFormatter();

  const [more, setMore] = useState<boolean>(false);

  const { mandatoryAttributes } = useIsMandatoryAttribute(NOTE_TYPE);

  const initialValues = useDefaultValues<NoteAddInput>(NOTE_TYPE, {
    attribute_abstract: '',
    content: '',
    likelihood: 50,
    confidence: undefined,
    note_types: [],
    objectMarking: toOptions(defaultMarkings),
    objectLabel: [],
  });

  const basicShape = yupShapeConditionalRequired({
    content: Yup.string().trim().min(2),
    attribute_abstract: Yup.string().nullable(),
    confidence: Yup.number(),
    note_types: Yup.array(),
    likelihood: Yup.number().min(0).max(100),
  }, mandatoryAttributes);

  // created & createdBy must be excluded from the validation, it will be handled directly by the backend
  const noteValidator = useDynamicSchemaCreationValidation(
    mandatoryAttributes,
    basicShape,
    ['created', 'createdBy'],
  );

  const handleToggleMore = () => {
    setMore(!more);
  };

  useEffect(() => {
    onToggleMore();
  }, [more]);

  return (
    <Formik<NoteAddInput>
      initialValues={initialValues}
      validationSchema={noteValidator}
      onSubmit={onSubmit}
      onReset={onToggleWrite}
    >
      {({
        submitForm,
        handleReset,
        setFieldValue,
        values,
        isSubmitting,
      }) => (
        <Stack gap={2}>
          <Box>
            <Field
              component={MarkdownField}
              name="content"
              label={t_i18n('Content')}
              required={(mandatoryAttributes.includes('content'))}
              fullWidth={true}
              multiline={true}
              rows="4"
            />
            <ObjectMarkingField
              name="objectMarking"
              required={(mandatoryAttributes.includes('objectMarking'))}
              style={fieldSpacingContainerStyle}
              setFieldValue={setFieldValue}
            />
            {
              more && (
                <>
                  <Field
                    component={TextField}
                    name="attribute_abstract"
                    label={t_i18n('Abstract')}
                    required={(mandatoryAttributes.includes('attribute_abstract'))}
                    fullWidth={true}
                    style={{ marginTop: 20 }}
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
                    label={t_i18n('Likelihood')}
                    fullWidth={true}
                    style={{ marginTop: 20 }}
                  />
                  <ObjectLabelField
                    name="objectLabel"
                    required={(mandatoryAttributes.includes('objectLabel'))}
                    style={{ marginTop: 10, width: '100%' }}
                    setFieldValue={setFieldValue}
                    values={values.objectLabel}
                  />
                </>
              )
            }
          </Box>

          <Stack direction="row" justifyContent="space-between">
            <Button
              onClick={handleToggleMore}
              disabled={isSubmitting}
              size="small"
              endIcon={
                more ? <ExpandLessOutlined /> : <ExpandMoreOutlined />
              }
            >
              {more ? t_i18n('Less fields') : t_i18n('More fields')}
            </Button>

            <Stack direction="row" spacing={1}>
              <Button
                variant="secondary"
                onClick={handleReset}
                disabled={isSubmitting}
                size="small"
              >
                {t_i18n('Cancel')}
              </Button>
              <Button
                onClick={submitForm}
                disabled={isSubmitting}
                size="small"
              >
                {t_i18n('Create')}
              </Button>
            </Stack>
          </Stack>
        </Stack>
      )}
    </Formik>
  );
};

const StixCoreObjectOrStixCoreRelationshipNotesCards: FunctionComponent<
  StixCoreObjectOrStixCoreRelationshipNotesCardsProps
> = ({
  id,
  marginTop = 0,
  queryRef,
  paginationOptions,
  defaultMarkings,
  title,
}) => {
  const { t_i18n } = useFormatter();

  const data = usePreloadedFragment<
    StixCoreObjectOrStixCoreRelationshipNotesCardsQuery,
    StixCoreObjectOrStixCoreRelationshipNotesCards_data$key
  >({
    queryDef: stixCoreObjectOrStixCoreRelationshipNotesCardsQuery,
    fragmentDef: stixCoreObjectOrStixCoreRelationshipNotesCardsFragment,
    queryRef,
  });

  const notes = data?.notes?.edges ?? [];
  const containerRef = useRef<HTMLDivElement>(null);

  const [open, setOpen] = useState<boolean>(false);

  const scrollToBottom = () => {
    const element = containerRef.current;
    if (!element) return;

    setTimeout(() => {
      const rect = element.getBoundingClientRect();
      const targetPosition = rect.bottom + window.pageYOffset + marginTop;

      window.scrollTo({
        top: targetPosition,
        behavior: 'smooth',
      });
    }, 200);
  };

  const scrollToTop = () => {
    const element = containerRef.current;
    if (!element) return;

    setTimeout(() => {
      const rect = element.getBoundingClientRect();
      const OFFSET_TITLE_BLOCK = 100; // arbitrary offset to see the title block
      const targetPosition = rect.top + window.pageYOffset - marginTop - OFFSET_TITLE_BLOCK;

      window.scrollTo({
        top: targetPosition,
        behavior: 'smooth',
      });
    }, 100);
  };

  useEffect(() => {
    if (containerRef.current && open) {
      scrollToBottom();
    }
  }, [open]);

  const handleToggleWrite = () => {
    setOpen(!open);
  };

  const handleMore = () => {
    scrollToBottom();
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
        scrollToTop();
      },
    });
  };

  return (
    <div style={{ marginTop, marginBottom: 20 }} ref={containerRef}>
      <Header
        data={data}
        id={id}
        onToggleWrite={handleToggleWrite}
        paginationOptions={paginationOptions}
        title={title}
      />

      {
        notes.map(({ node }) => {
          return (
            <StixCoreObjectOrStixCoreRelationshipNoteCard
              key={node.id}
              data={node}
              stixCoreObjectOrStixCoreRelationshipId={id}
              paginationOptions={paginationOptions}
            />
          );
        })
      }

      <Security needs={[KNOWLEDGE_KNPARTICIPATE]}>
        <Accordion
          expanded={open}
          variant="outlined"
          sx={{
            spacing: 1,
            borderBottomLeftRadius: '4px!important', // override mui theme accordion
            borderBottomRightRadius: '4px!important',
            borderRadius: 1,
            '&:before': { backgroundColor: 'transparent' },
          }}
        >
          <AccordionSummary
            expandIcon={<ExpandMoreOutlined />}
            onClick={handleToggleWrite}
            sx={{ spacing: 1 }}
          >
            <Stack direction="row" spacing={1}>
              <RateReviewOutlined />
              <Typography>{t_i18n('Write a note')}</Typography>
            </Stack>
          </AccordionSummary>

          <AccordionDetails>
            <NoteForm
              defaultMarkings={defaultMarkings}
              onToggleWrite={handleToggleWrite}
              onToggleMore={handleMore}
              onSubmit={onSubmit}
            />
          </AccordionDetails>
        </Accordion>
      </Security>
    </div>
  );
};

export default StixCoreObjectOrStixCoreRelationshipNotesCards;
