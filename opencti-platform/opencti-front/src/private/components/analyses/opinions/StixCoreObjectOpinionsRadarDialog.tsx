import React, { FunctionComponent, useState } from 'react';
import IconButton from '@mui/material/IconButton';
import Slider from '@mui/material/Slider';
import { ThumbsUpDownOutlined } from '@mui/icons-material';
import DialogTitle from '@mui/material/DialogTitle';
import DialogContent from '@mui/material/DialogContent';
import DialogActions from '@mui/material/DialogActions';
import Button from '@mui/material/Button';
import Dialog from '@mui/material/Dialog';
import { Field, Form, Formik } from 'formik';
import { graphql, useMutation, usePreloadedQuery } from 'react-relay';
import { PreloadedQuery } from 'react-relay/relay-hooks/EntryPointTypes';
import { FormikHelpers } from 'formik/dist/types';
import { useFormatter } from '../../../../components/i18n';
import Security from '../../../../utils/Security';
import useGranted, {
  KNOWLEDGE_KNPARTICIPATE,
  KNOWLEDGE_KNUPDATE,
} from '../../../../utils/hooks/useGranted';
import {
  opinionCreationMutation,
  opinionCreationUserMutation,
} from './OpinionCreation';
import MarkdownField from '../../../../components/MarkdownField';
import { adaptFieldValue } from '../../../../utils/String';
import { opinionMutationFieldPatch } from './OpinionEditionOverview';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import ConfidenceField from '../../common/form/ConfidenceField';
import { isNotEmptyField } from '../../../../utils/utils';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import { StixCoreObjectOpinionsRadarDialogMyOpinionQuery } from './__generated__/StixCoreObjectOpinionsRadarDialogMyOpinionQuery.graphql';

export const stixCoreObjectOpinionsRadarDialogMyOpinionQuery = graphql`
  query StixCoreObjectOpinionsRadarDialogMyOpinionQuery($id: String!) {
    myOpinion(id: $id) {
      id
      opinion
      explanation
      confidence
    }
  }
`;

interface StixCoreObjectOpinionsRadarDialogProps {
  queryRef: PreloadedQuery<StixCoreObjectOpinionsRadarDialogMyOpinionQuery>
  stixCoreObjectId: string
  fetchQuery: () => void
  opinionOptions: { label: string, value: number }[]
}

interface OpinionAddInput {
  alreadyExistingOpinion: string;
  explanation: string;
  confidence: number;
}
interface OpinionAddSubmit {
  opinion: string;
  explanation: string;
  confidence: number;
  objects?: string[];
}

const StixCoreObjectOpinionsDialogComponent: FunctionComponent<
StixCoreObjectOpinionsRadarDialogProps
> = ({
  queryRef,
  stixCoreObjectId,
  fetchQuery,
  opinionOptions,
}) => {
  const { t } = useFormatter();
  const { myOpinion } = usePreloadedQuery<StixCoreObjectOpinionsRadarDialogMyOpinionQuery>(
    stixCoreObjectOpinionsRadarDialogMyOpinionQuery,
    queryRef,
  );

  const myOpinionValue = opinionOptions.find(
    (m) => m.label === myOpinion?.opinion,
  )?.value;
  const [currentOpinion, setCurrentOpinion] = useState(
    myOpinionValue ?? Math.round(opinionOptions.length / 2),
  );
  const [open, setOpen] = useState(false);
  const handleOpen = () => setOpen(true);
  const handleClose = () => setOpen(false);
  const userIsKnowledgeEditor = useGranted([KNOWLEDGE_KNUPDATE]);
  const [commitCreation] = useMutation(
    userIsKnowledgeEditor
      ? opinionCreationMutation
      : opinionCreationUserMutation,
  );
  const [commitEdition] = useMutation(opinionMutationFieldPatch);
  const onSubmit = (
    values: OpinionAddInput,
    { setSubmitting, resetForm }: FormikHelpers<OpinionAddInput>,
  ) => {
    const { alreadyExistingOpinion, explanation, confidence } = values;
    let inputValues: OpinionAddSubmit = {
      opinion: opinionOptions[currentOpinion - 1].label,
      explanation,
      confidence: parseInt(String(confidence), 10),
    };
    if (isNotEmptyField(alreadyExistingOpinion)) {
      const finalValues = Object.entries(inputValues).map(([key, value]) => ({
        key,
        value: adaptFieldValue(value),
      }));
      commitEdition({
        variables: {
          id: alreadyExistingOpinion,
          input: finalValues,
        },
        onCompleted: () => {
          handleClose();
          setSubmitting(false);
          resetForm();
          fetchQuery();
        },
      });
    } else {
      inputValues = { ...inputValues, objects: [stixCoreObjectId] };
      commitCreation({
        variables: {
          input: inputValues,
        },
        onCompleted: () => {
          handleClose();
          setSubmitting(false);
          resetForm();
          fetchQuery();
        },
      });
    }
  };
  return (
    <Security needs={[KNOWLEDGE_KNUPDATE, KNOWLEDGE_KNPARTICIPATE]}>
      <>
        <IconButton
          color="secondary"
          aria-label="Label"
          onClick={handleOpen}
          style={{
            float: 'left',
            margin: '-15px 0 0 -2px',
          }}
          size="large"
        >
          <ThumbsUpDownOutlined fontSize="small" />
        </IconButton>
        <Dialog
          PaperProps={{ elevation: 1 }}
          open={open}
          onClose={handleClose}
          fullWidth={true}
        >
          <Formik
            enableReinitialize={true}
            initialValues={{
              alreadyExistingOpinion: myOpinion?.id ?? '',
              explanation: myOpinion?.explanation ?? '',
              confidence: myOpinion?.confidence ?? 75,
            }}
            onSubmit={onSubmit}
            onReset={handleClose}
          >
            {({ submitForm, handleReset, isSubmitting }) => (
              <Form>
                <DialogTitle>
                  {myOpinion ? t('Update opinion') : t('Create an opinion')}
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
                      value={currentOpinion}
                      onChange={(_, v) => setCurrentOpinion(v as number)}
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
                    label={t('Explanation')}
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
                  <Button onClick={handleReset} disabled={isSubmitting}>
                    {t('Cancel')}
                  </Button>
                  <Button
                    color="secondary"
                    onClick={submitForm}
                    disabled={isSubmitting}
                  >
                    {myOpinion ? t('Update') : t('Create')}
                  </Button>
                </DialogActions>
              </Form>
            )}
          </Formik>
        </Dialog>
      </>
    </Security>
  );
};

const StixCoreObjectOpinionsDialog: FunctionComponent<Omit<StixCoreObjectOpinionsRadarDialogProps, 'queryRef'>> = (
  props,
) => {
  const queryRef = useQueryLoading<StixCoreObjectOpinionsRadarDialogMyOpinionQuery>(stixCoreObjectOpinionsRadarDialogMyOpinionQuery, {
    id: props.stixCoreObjectId,
  });
  return queryRef ? (
    <React.Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
      <StixCoreObjectOpinionsDialogComponent {...props} queryRef={queryRef} />
    </React.Suspense>
  ) : (
    <Loader variant={LoaderVariant.inElement} />
  );
};

export default StixCoreObjectOpinionsDialog;
