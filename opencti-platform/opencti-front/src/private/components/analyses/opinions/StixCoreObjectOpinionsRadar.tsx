import React, { FunctionComponent, useState } from 'react';
import * as R from 'ramda';
import Typography from '@mui/material/Typography';
import Paper from '@mui/material/Paper';
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
import makeStyles from '@mui/styles/makeStyles';
import { useTheme } from '@mui/styles';
import { PreloadedQuery } from 'react-relay/relay-hooks/EntryPointTypes';
import { FormikHelpers } from 'formik/dist/types';
import Chart from '../../common/charts/Chart';
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
import { radarChartOptions } from '../../../../utils/Charts';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import ConfidenceField from '../../common/form/ConfidenceField';
import { generateGreenToRedColors } from '../../../../utils/Colors';
import { StixCoreObjectOpinionsRadarDistributionQuery } from './__generated__/StixCoreObjectOpinionsRadarDistributionQuery.graphql';
import { isNotEmptyField } from '../../../../utils/utils';

const useStyles = makeStyles(() => ({
  paper: {
    height: 300,
    minHeight: 300,
    maxHeight: 300,
    margin: '10px 0 0 0',
    padding: 0,
    borderRadius: 6,
  },
}));

export const stixCoreObjectOpinionsRadarFragmentQuery = graphql`
  query StixCoreObjectOpinionsRadarDistributionQuery(
    $objectId: String
    $field: String!
    $operation: StatsOperation!
    $limit: Int
    $category: VocabularyCategory!
    $id: String!
  ) {
    opinionsDistribution(
      objectId: $objectId
      field: $field
      operation: $operation
      limit: $limit
    ) {
      label
      value
      entity {
        ... on Identity {
          name
        }
        ... on Malware {
          name
        }
      }
    }
    vocabularies(category: $category) {
      edges {
        node {
          id
          name
          description
          order
        }
      }
    }
    myOpinion(id: $id) {
      id
      opinion
      explanation
      confidence
    }
  }
`;

interface StixCoreObjectOpinionsRadarProps {
  stixCoreObjectId: string;
  queryRef: PreloadedQuery<StixCoreObjectOpinionsRadarDistributionQuery>;
  fetchQuery: () => void;
  variant: string;
  height: number;
  marginTop: number;
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

const StixCoreObjectOpinionsRadar: FunctionComponent<
StixCoreObjectOpinionsRadarProps
> = ({
  stixCoreObjectId,
  queryRef,
  fetchQuery,
  variant,
  height,
  marginTop,
}) => {
  const classes = useStyles();
  const { t } = useFormatter();
  const theme = useTheme();
  const data = usePreloadedQuery<StixCoreObjectOpinionsRadarDistributionQuery>(
    stixCoreObjectOpinionsRadarFragmentQuery,
    queryRef,
  );
  const { opinionsDistribution, vocabularies, myOpinion } = data;
  const opinionOptions = vocabularies?.edges
    .map((edge) => edge.node)
    .sort((n1, n2) => {
      if (n1.order === n2.order) {
        return n1.name.localeCompare(n2.name);
      }
      return (n1.order ?? 0) - (n2.order ?? 0);
    })
    .map((node, idx) => ({
      label: node.name.toLowerCase(),
      value: idx + 1,
    })) ?? [];

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
          fetchQuery();
          setSubmitting(false);
          resetForm();
          handleClose();
        },
      });
    } else {
      inputValues = { ...inputValues, objects: [stixCoreObjectId] };
      commitCreation({
        variables: {
          input: inputValues,
        },
        onCompleted: () => {
          fetchQuery();
          setSubmitting(false);
          resetForm();
          handleClose();
        },
      });
    }
  };
  const renderContent = () => {
    const distributionData = R.indexBy(
      R.prop('label'),
      (opinionsDistribution || []).map((n) => ({
        ...n,
        label: n?.label.toLowerCase(),
      })),
    );
    const chartData = [
      {
        name: t('Opinions'),
        data: opinionOptions.map((m) => distributionData[m.label]?.value || 0),
      },
    ];
    const labels = opinionOptions.map((m) => m.label);
    const colors = generateGreenToRedColors(opinionOptions.length);
    return (
      <Chart
        // eslint-disable-next-line @typescript-eslint/ban-ts-comment
        // @ts-ignore
        // Need to migrate Chart Charts.js file to TSX
        options={radarChartOptions(theme, labels, colors, true, true)}
        series={chartData}
        type="radar"
        width="100%"
        height={height}
      />
    );
  };
  return (
    <div style={{ height: height || '100%', marginTop: marginTop || 0 }}>
      <Typography
        variant={variant === 'inEntity' ? 'h3' : 'h4'}
        gutterBottom={true}
        style={{ float: 'left' }}
      >
        {t('Distribution of opinions')}
      </Typography>
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
      <div className="clearfix" />
      {variant === 'inLine' || variant === 'inEntity' ? (
        renderContent()
      ) : (
        <Paper classes={{ root: classes.paper }} variant="outlined">
          {renderContent()}
        </Paper>
      )}
    </div>
  );
};

export default StixCoreObjectOpinionsRadar;
