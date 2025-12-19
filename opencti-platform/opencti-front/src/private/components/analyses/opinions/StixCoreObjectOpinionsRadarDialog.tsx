import React, { FunctionComponent, useCallback, useEffect, useState } from 'react';
import IconButton from '@common/button/IconButton';
import * as Yup from 'yup';
import Slider from '@mui/material/Slider';
import { ThumbsUpDownOutlined } from '@mui/icons-material';
import DialogTitle from '@mui/material/DialogTitle';
import DialogContent from '@mui/material/DialogContent';
import DialogActions from '@mui/material/DialogActions';
import Button from '@common/button/Button';
import Dialog from '@mui/material/Dialog';
import { Field, Form, Formik } from 'formik';
import { graphql, usePreloadedQuery, useQueryLoader } from 'react-relay';
import { PreloadedQuery } from 'react-relay/relay-hooks/EntryPointTypes';
import { FormikHelpers } from 'formik/dist/types';
import { useFormatter } from '../../../../components/i18n';
import Security from '../../../../utils/Security';
import useGranted, { KNOWLEDGE_KNPARTICIPATE, KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';
import { opinionCreationMutation, opinionCreationUserMutation } from './OpinionCreation';
import MarkdownField from '../../../../components/fields/MarkdownField';
import { adaptFieldValue } from '../../../../utils/String';
import { opinionMutationFieldPatch } from './OpinionEditionOverview';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import ConfidenceField from '../../common/form/ConfidenceField';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import {
  StixCoreObjectOpinionsRadarDialogMyOpinionQuery,
  StixCoreObjectOpinionsRadarDialogMyOpinionQuery$variables,
} from './__generated__/StixCoreObjectOpinionsRadarDialogMyOpinionQuery.graphql';
import { MESSAGING$ } from '../../../../relay/environment';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { yupShapeConditionalRequired, useDynamicSchemaCreationValidation, useIsMandatoryAttribute } from '../../../../utils/hooks/useEntitySettings';
import useDefaultValues from '../../../../utils/hooks/useDefaultValues';

export const stixCoreObjectOpinionsRadarDialogMyOpinionQuery = graphql`
  query StixCoreObjectOpinionsRadarDialogMyOpinionQuery($id: String!) {
    myOpinion(id: $id) {
      id
      standard_id
      opinion
      explanation
      confidence
    }
  }
`;

interface StixCoreObjectOpinionsRadarDialogProps {
  queryRef: PreloadedQuery<StixCoreObjectOpinionsRadarDialogMyOpinionQuery>;
  stixCoreObjectId: string;
  fetchQuery: () => void;
  fetchDistributionQuery: () => void;
  opinionOptions: { label: string; value: number }[];
}

interface OpinionAddInput {
  id?: string;
  opinion: string;
  explanation: string;
  confidence: number;
}
interface OpinionAddSubmit {
  opinion: string;
  explanation: string;
  confidence: number;
  objects?: string[];
}

const OPINION_TYPE = 'Opinion';

const StixCoreObjectOpinionsDialogComponent: FunctionComponent<
  StixCoreObjectOpinionsRadarDialogProps
> = ({
  queryRef,
  stixCoreObjectId,
  fetchQuery,
  fetchDistributionQuery,
  opinionOptions,
}) => {
  const { t_i18n } = useFormatter();
  const { myOpinion } = usePreloadedQuery<StixCoreObjectOpinionsRadarDialogMyOpinionQuery>(
    stixCoreObjectOpinionsRadarDialogMyOpinionQuery,
    queryRef,
  );
  const { mandatoryAttributes } = useIsMandatoryAttribute(OPINION_TYPE);
  const basicShape = yupShapeConditionalRequired({
    opinion: Yup.string(),
    explanation: Yup.string(),
    confidence: Yup.number(),
  }, mandatoryAttributes);
  const opinionValidator = useDynamicSchemaCreationValidation(
    mandatoryAttributes,
    basicShape,
    ['opinion'], // exclude these fields because their components don't support validation
  );

  const [open, setOpen] = useState(false);
  const handleOpen = () => {
    if (opinionOptions.length > 0) {
      setOpen(true);
    } else {
      MESSAGING$.notifyError(
        <span>
          {t_i18n('The opinions has no value defined in your vocabulary. Please add them first to be able to add opinions.')}
        </span>,
      );
    }
  };
  const handleClose = () => setOpen(false);
  const userIsKnowledgeEditor = useGranted([KNOWLEDGE_KNUPDATE]);
  const [commitCreation] = useApiMutation(
    userIsKnowledgeEditor
      ? opinionCreationMutation
      : opinionCreationUserMutation,
  );
  const [commitEdition] = useApiMutation(opinionMutationFieldPatch);
  const onSubmit = (
    values: OpinionAddInput,
    { setSubmitting, resetForm }: FormikHelpers<OpinionAddInput>,
  ) => {
    const { id, ...inputValues } = values;
    let parsedConfidence = parseInt(String(inputValues.confidence), 10);
    if (Number.isNaN(parsedConfidence)) parsedConfidence = 0;
    const baseInput: OpinionAddSubmit = {
      ...inputValues,
      confidence: parsedConfidence,
    };
    if (id) {
      const input = Object.entries(baseInput).map(([key, value]) => ({
        key,
        value: adaptFieldValue(value),
      }));
      commitEdition({
        variables: { id, input },
        onCompleted: () => {
          handleClose();
          setSubmitting(false);
          resetForm();
          fetchQuery();
          fetchDistributionQuery();
        },
      });
    } else {
      const input: OpinionAddSubmit = {
        ...baseInput,
        objects: [stixCoreObjectId],
      };
      commitCreation({
        variables: { input },
        onCompleted: () => {
          handleClose();
          setSubmitting(false);
          resetForm();
          fetchQuery();
          fetchDistributionQuery();
        },
      });
    }
  };

  const initialValues = useDefaultValues<OpinionAddInput>(
    OPINION_TYPE,
    {
      id: myOpinion?.id,
      opinion: myOpinion?.opinion
        ?? (opinionOptions.length > 0 ? opinionOptions[Math.floor(opinionOptions.length / 2)].label : 'default'),
      explanation: myOpinion?.explanation ?? '',
      confidence: myOpinion?.confidence ?? 75,
    },
  );

  return (
    <Security needs={[KNOWLEDGE_KNUPDATE, KNOWLEDGE_KNPARTICIPATE]}>
      <>
        <IconButton
          color="primary"
          aria-label="Label"
          onClick={handleOpen}
          style={{
            float: 'left',
            margin: '-15px 0 0 -2px',
          }}
        >
          <ThumbsUpDownOutlined fontSize="small" />
        </IconButton>
        {opinionOptions.length > 0 && (
          <Dialog
            slotProps={{ paper: { elevation: 1 } }}
            open={open}
            onClose={handleClose}
            fullWidth={true}
          >
            <Formik<OpinionAddInput>
              enableReinitialize={true}
              initialValues={initialValues}
              validationSchema={opinionValidator}
              validateOnChange={true}
              validateOnBlur={true}
              onSubmit={onSubmit}
              onReset={handleClose}
            >
              {({ submitForm, handleReset, isSubmitting, values, setFieldValue }) => (
                <Form>
                  <DialogTitle>
                    {myOpinion ? t_i18n('Update opinion') : t_i18n('Create an opinion')}
                  </DialogTitle>
                  <DialogContent>
                    <div style={{ marginLeft: 10, marginRight: 10 }}>
                      <Slider
                        sx={{
                          '& .MuiSlider-markLabel': {
                            textOverflow: 'ellipsis',
                            maxWidth: 60,
                            overflow: 'hidden',
                          },
                          '& .MuiSlider-thumb[style*="left: 0%"] .MuiSlider-valueLabelOpen':
                            {
                              left: -5,
                              '&:before': {
                                left: '22%',
                              },
                            },
                          '& .MuiSlider-thumb[style*="left: 100%"] .MuiSlider-valueLabelOpen':
                            {
                              right: -5,
                              '&:before': {
                                left: '88%',
                              },
                            },
                        }}
                        style={{ marginTop: 30 }}
                        value={opinionOptions.find((o) => o.label === values.opinion)?.value}
                        onChange={(_, v) => {
                          setFieldValue('opinion', opinionOptions.find(
                            (m) => m.value === v,
                          )?.label);
                        }}
                        valueLabelDisplay="on"
                        valueLabelFormat={(v) => opinionOptions[v - 1].label}
                        marks={opinionOptions}
                        step={1}
                        min={1}
                        max={opinionOptions.length}
                      />
                    </div>
                    <Field
                      component={MarkdownField}
                      name="explanation"
                      label={t_i18n('Explanation')}
                      required={(mandatoryAttributes.includes('explanation'))}
                      fullWidth={true}
                      multiline={true}
                      rows="4"
                      style={fieldSpacingContainerStyle}
                    />
                    <ConfidenceField
                      entityType="Opinion"
                      containerStyle={fieldSpacingContainerStyle}
                    />
                  </DialogContent>
                  <DialogActions>
                    <Button variant="secondary" onClick={handleReset} disabled={isSubmitting}>
                      {t_i18n('Cancel')}
                    </Button>
                    <Button
                      onClick={submitForm}
                      disabled={isSubmitting}
                    >
                      {myOpinion ? t_i18n('Update') : t_i18n('Create')}
                    </Button>
                  </DialogActions>
                </Form>
              )}
            </Formik>
          </Dialog>
        )}
      </>
    </Security>
  );
};

const StixCoreObjectOpinionsDialog: FunctionComponent<Omit<StixCoreObjectOpinionsRadarDialogProps, 'queryRef' | 'fetchQuery'>> = (
  props,
) => {
  const variables: StixCoreObjectOpinionsRadarDialogMyOpinionQuery$variables = {
    id: props.stixCoreObjectId,
  };
  const [queryRef, fetchLoadQuery] = useQueryLoader<StixCoreObjectOpinionsRadarDialogMyOpinionQuery>(
    stixCoreObjectOpinionsRadarDialogMyOpinionQuery,
  );
  const fetchQuery = useCallback(
    () => fetchLoadQuery(variables, { fetchPolicy: 'network-only' }),
    [],
  );
  useEffect(
    () => fetchLoadQuery(variables, { fetchPolicy: 'store-and-network' }),
    [],
  );
  return queryRef ? (
    <React.Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
      <StixCoreObjectOpinionsDialogComponent {...props} queryRef={queryRef} fetchQuery={fetchQuery} />
    </React.Suspense>
  ) : (
    <Loader variant={LoaderVariant.inElement} />
  );
};

export default StixCoreObjectOpinionsDialog;
