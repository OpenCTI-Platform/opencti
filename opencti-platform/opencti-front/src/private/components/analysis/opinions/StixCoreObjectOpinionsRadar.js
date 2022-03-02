import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import {
  ResponsiveContainer,
  RadarChart,
  PolarGrid,
  PolarAngleAxis,
  Radar,
} from 'recharts';
import withTheme from '@mui/styles/withTheme';
import withStyles from '@mui/styles/withStyles';
import CircularProgress from '@mui/material/CircularProgress';
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
import { graphql, createRefetchContainer } from 'react-relay';
import { commitMutation, QueryRenderer } from '../../../../relay/environment';
import inject18n from '../../../../components/i18n';
import Security, { KNOWLEDGE_KNUPDATE } from '../../../../utils/Security';
import { opinionCreationMutation } from './OpinionCreation';
import MarkDownField from '../../../../components/MarkDownField';
import { adaptFieldValue } from '../../../../utils/String';
import { opinionMutationFieldPatch } from './OpinionEditionOverview';

const styles = () => ({
  paper: {
    height: 300,
    minHeight: 300,
    maxHeight: 300,
    margin: '10px 0 0 0',
    padding: 0,
    borderRadius: 6,
  },
  'strongly-disagree': {
    fontSize: 12,
    backgroundColor: '#ff5722',
  },
  disagree: {
    fontSize: 12,
    color: '#ffc107',
  },
  neutral: {
    fontSize: 12,
    color: '#cddc39',
  },
  agree: {
    fontSize: 12,
    color: '#8bc34a',
  },
  'strongly-agree': {
    fontSize: 12,
    color: '#4caf50',
  },
});

const stixCoreObjectOpinionsRadarMyOpinionQuery = graphql`
  query StixCoreObjectOpinionsRadarMyOpinionQuery($id: String!) {
    myOpinion(id: $id) {
      id
      opinion
      explanation
    }
  }
`;

const colors = {
  'strongly-disagree': '#ff5722',
  disagree: '#ffc107',
  neutral: '#cddc39',
  agree: '#8bc34a',
  'strongly-agree': '#4caf50',
};

const opinions = [
  'strongly-disagree',
  'disagree',
  'neutral',
  'agree',
  'strongly-agree',
];

class StixCoreObjectOpinionsRadarComponent extends Component {
  constructor(props) {
    super(props);
    this.state = { open: false, currentOpinion: null };
  }

  handleOpen() {
    this.setState({ open: true });
  }

  handleClose() {
    this.setState({ open: false });
  }

  handleChangeCurrentOpinion(event, value) {
    this.setState({ currentOpinion: value });
  }

  tickFormatter(props) {
    const { classes } = this.props;
    const { payload, x, y, textAnchor } = props;
    const color = colors[payload.value];
    return (
      <text
        x={x}
        y={y}
        textAnchor={textAnchor}
        fill={color}
        className={classes[payload.value]}
      >
        {payload.value}
      </text>
    );
  }

  onSubmit(values, { setSubmitting, resetForm }) {
    const { currentOpinion } = this.state;
    const { alreadyExistingOpinion } = values;
    const { stixCoreObjectId, data, paginationOptions } = this.props;
    const defaultMarking = R.pathOr(
      [],
      ['stixCoreObject', 'objectMarking', 'edges'],
      data,
    ).map((n) => n.node.id);
    if (alreadyExistingOpinion) {
      const inputValues = R.pipe(
        R.dissoc('alreadyExistingOpinion'),
        R.assoc('opinion', opinions[(currentOpinion || 3) - 1]),
        R.assoc('objectMarking', defaultMarking),
        R.toPairs,
        R.map((n) => ({
          key: n[0],
          value: adaptFieldValue(n[1]),
        })),
      )(values);
      commitMutation({
        mutation: opinionMutationFieldPatch,
        variables: {
          id: alreadyExistingOpinion,
          input: inputValues,
        },
        onCompleted: () => {
          this.props.relay.refetch(paginationOptions);
          setSubmitting(false);
          resetForm();
        },
      });
    } else {
      const adaptedValues = R.pipe(
        R.dissoc('alreadyExistingOpinion'),
        R.assoc('opinion', opinions[(currentOpinion || 3) - 1]),
        R.assoc('objectMarking', defaultMarking),
        R.assoc('objects', [stixCoreObjectId]),
      )(values);
      commitMutation({
        mutation: opinionCreationMutation,
        variables: {
          input: adaptedValues,
        },
        setSubmitting,
        onCompleted: () => {
          this.props.relay.refetch(paginationOptions);
          setSubmitting(false);
          resetForm();
        },
      });
    }
  }

  onReset() {
    this.handleClose();
  }

  renderContent() {
    const { t, data, field, theme } = this.props;
    if (data && data.opinionsDistribution) {
      let distributionData;
      if (field && field.includes('internal_id')) {
        distributionData = R.map(
          (n) => R.assoc('label', n.entity.name, n),
          data.opinionsDistribution,
        );
      } else {
        distributionData = R.map(
          (n) => R.assoc('label', n.label.toLowerCase(), n),
          data.opinionsDistribution,
        );
      }
      distributionData = R.indexBy(R.prop('label'), distributionData);
      const radarData = [
        {
          label: 'strongly-disagree',
          value: distributionData['strongly-disagree']?.value || 0,
        },
        {
          label: 'disagree',
          value: distributionData.disagree?.value || 0,
        },
        {
          label: 'neutral',
          value: distributionData.neutral?.value || 0,
        },
        {
          label: 'agree',
          value: distributionData.agree?.value || 0,
        },
        {
          label: 'strongly-agree',
          value: distributionData['strongly-agree']?.value || 0,
        },
      ];

      return (
        <div
          style={{
            width: '100%',
            height: '100%',
            marginLeft: -50,
          }}
        >
          <ResponsiveContainer width="100%" height="100%">
            <RadarChart
              cx="50%"
              cy="50%"
              outerRadius="60%"
              data={radarData}
              margin={{
                top: 0,
                right: 0,
                bottom: 0,
                left: 0,
              }}
            >
              <PolarGrid
                stroke={
                  theme.palette.mode === 'dark'
                    ? 'rgba(255, 255, 255, .1)'
                    : 'rgba(0, 0, 0, .1)'
                }
              />
              <PolarAngleAxis
                dataKey="label"
                tick={(innerProps) => this.tickFormatter(innerProps)}
              />
              <Radar
                dataKey="value"
                stroke={theme.palette.primary.main}
                fill={theme.palette.primary.main}
                fillOpacity={0.3}
              />
            </RadarChart>
          </ResponsiveContainer>
        </div>
      );
    }

    if (data) {
      return (
        <div
          style={{
            display: 'table',
            height: '100%',
            width: '100%',
          }}
        >
          <span
            style={{
              display: 'table-cell',
              verticalAlign: 'middle',
              textAlign: 'center',
            }}
          >
            {t('No entities of this type has been found.')}
          </span>
        </div>
      );
    }
    return (
      <div
        style={{
          display: 'table',
          height: '100%',
          width: '100%',
        }}
      >
        <span
          style={{
            display: 'table-cell',
            verticalAlign: 'middle',
            textAlign: 'center',
          }}
        >
          <CircularProgress size={40} thickness={2} />
        </span>
      </div>
    );
  }

  render() {
    const { currentOpinion } = this.state;
    const { t, classes, title, variant, height, marginTop, stixCoreObjectId } = this.props;
    const marks = [
      { label: '-', value: 1 },
      { label: t('disagree'), value: 2 },
      { label: t('neutral'), value: 3 },
      { label: t('agree'), value: 4 },
      { label: '+', value: 5 },
    ];
    return (
      <div style={{ height: height || '100%', marginTop: marginTop || 0 }}>
        <Typography
          variant={variant === 'inEntity' ? 'h3' : 'h4'}
          gutterBottom={true}
          style={{ float: 'left' }}
        >
          {title || t('Distribution of opinions')}
        </Typography>
        <Security needs={[KNOWLEDGE_KNUPDATE]}>
          <IconButton
            color="secondary"
            aria-label="Label"
            onClick={this.handleOpen.bind(this)}
            style={{ float: 'left', margin: '-15px 0 0 -2px' }}
            size="large"
          >
            <ThumbsUpDownOutlined fontSize="small" />
          </IconButton>
          <Dialog
            PaperProps={{ elevation: 1 }}
            open={this.state.open}
            onClose={this.handleClose.bind(this)}
          >
            <QueryRenderer
              query={stixCoreObjectOpinionsRadarMyOpinionQuery}
              variables={{ id: stixCoreObjectId }}
              render={({ props }) => {
                if (props) {
                  const explanation = R.propOr(
                    '',
                    'explanation',
                    props.myOpinion,
                  );
                  const opinion = opinions.indexOf(
                    R.propOr(currentOpinion, 'opinion', props.myOpinion),
                  ) + 1;
                  return (
                    <Formik
                      enableReinitialize={true}
                      initialValues={{
                        alreadyExistingOpinion: props.myOpinion?.id || '',
                        explanation,
                      }}
                      onSubmit={this.onSubmit.bind(this)}
                      onReset={this.onReset.bind(this)}
                    >
                      {({ submitForm, handleReset, isSubmitting }) => (
                        <Form>
                          <DialogTitle>{t('Update opinion')}</DialogTitle>
                          <DialogContent>
                            <Slider
                              style={{ marginTop: 30 }}
                              value={currentOpinion || opinion || 3}
                              onChange={this.handleChangeCurrentOpinion.bind(
                                this,
                              )}
                              step={1}
                              valueLabelDisplay="on"
                              marks={marks}
                              min={1}
                              max={5}
                            />
                            <Field
                              component={MarkDownField}
                              name="explanation"
                              label={t('Explanation')}
                              fullWidth={true}
                              multiline={true}
                              rows="4"
                              style={{ marginTop: 20 }}
                            />
                          </DialogContent>
                          <DialogActions>
                            <Button
                              onClick={handleReset}
                              disabled={isSubmitting}
                            >
                              {t('Cancel')}
                            </Button>
                            <Button
                              color="secondary"
                              onClick={submitForm}
                              disabled={isSubmitting}
                            >
                              {t('Update')}
                            </Button>
                          </DialogActions>
                        </Form>
                      )}
                    </Formik>
                  );
                }
                return <div />;
              }}
            />
          </Dialog>
        </Security>
        <div className="clearfix" />
        {variant === 'inLine' || variant === 'inEntity' ? (
          this.renderContent()
        ) : (
          <Paper classes={{ root: classes.paper }} variant="outlined">
            {this.renderContent()}
          </Paper>
        )}
      </div>
    );
  }
}

StixCoreObjectOpinionsRadarComponent.propTypes = {
  stixCoreObjectId: PropTypes.string,
  data: PropTypes.object,
  title: PropTypes.string,
  field: PropTypes.string,
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
  variant: PropTypes.string,
  height: PropTypes.number,
  marginTop: PropTypes.number,
  paginationOptions: PropTypes.object,
};

export const stixCoreObjectOpinionsRadarDistributionQuery = graphql`
  query StixCoreObjectOpinionsRadarDistributionQuery(
    $objectId: String
    $field: String!
    $operation: StatsOperation!
    $limit: Int
  ) {
    ...StixCoreObjectOpinionsRadar_distribution
      @arguments(
        objectId: $objectId
        field: $field
        operation: $operation
        limit: $limit
      )
  }
`;

const StixCoreObjectOpinionsRadar = createRefetchContainer(
  StixCoreObjectOpinionsRadarComponent,
  {
    data: graphql`
      fragment StixCoreObjectOpinionsRadar_distribution on Query
      @argumentDefinitions(
        objectId: { type: "String" }
        field: { type: "String!" }
        operation: { type: "StatsOperation!" }
        limit: { type: "Int", defaultValue: 1000 }
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
      }
    `,
  },
  stixCoreObjectOpinionsRadarDistributionQuery,
);

export default R.compose(
  inject18n,
  withTheme,
  withStyles(styles),
)(StixCoreObjectOpinionsRadar);
