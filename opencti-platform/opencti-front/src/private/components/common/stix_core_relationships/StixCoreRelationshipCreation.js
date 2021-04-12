import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Formik, Form, Field } from 'formik';
import graphql from 'babel-plugin-relay/macro';
import {
  compose, map, pipe, pluck, head, assoc,
} from 'ramda';
import * as Yup from 'yup';
import { withStyles } from '@material-ui/core/styles';
import Drawer from '@material-ui/core/Drawer';
import Typography from '@material-ui/core/Typography';
import Button from '@material-ui/core/Button';
import IconButton from '@material-ui/core/IconButton';
import MenuItem from '@material-ui/core/MenuItem';
import Tooltip from '@material-ui/core/Tooltip';
import CircularProgress from '@material-ui/core/CircularProgress';
import { Close, ArrowRightAlt } from '@material-ui/icons';
import { fetchQuery, commitMutation } from '../../../../relay/environment';
import inject18n from '../../../../components/i18n';
import { itemColor } from '../../../../utils/Colors';
import { parse } from '../../../../utils/Time';
import { resolveRelationsTypes } from '../../../../utils/Relation';
import ItemIcon from '../../../../components/ItemIcon';
import MarkDownField from '../../../../components/MarkDownField';
import SelectField from '../../../../components/SelectField';
import DatePickerField from '../../../../components/DatePickerField';
import { truncate } from '../../../../utils/String';
import KillChainPhasesField from '../form/KillChainPhasesField';
import CreatedByField from '../form/CreatedByField';
import ObjectMarkingField from '../form/ObjectMarkingField';
import ConfidenceField from '../form/ConfidenceField';

const styles = (theme) => ({
  drawerPaper: {
    minHeight: '100vh',
    width: '50%',
    backgroundColor: theme.palette.navAlt.background,
    padding: 0,
  },
  createButton: {
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
  header: {
    backgroundColor: theme.palette.navAlt.backgroundHeader,
    padding: '20px 20px 20px 60px',
  },
  closeButton: {
    position: 'absolute',
    top: 12,
    left: 5,
  },
  importButton: {
    position: 'absolute',
    top: 15,
    right: 20,
  },
  container: {
    padding: '10px 20px 20px 20px',
  },
  item: {
    position: 'absolute',
    width: 180,
    height: 80,
    borderRadius: 10,
  },
  itemHeader: {
    padding: '10px 0 10px 0',
  },
  icon: {
    position: 'absolute',
    top: 8,
    left: 5,
    fontSize: 8,
  },
  type: {
    width: '100%',
    textAlign: 'center',
    color: '#ffffff',
    fontSize: 11,
  },
  content: {
    width: '100%',
    height: 40,
    maxHeight: 40,
    lineHeight: '40px',
    color: '#ffffff',
    textAlign: 'center',
  },
  name: {
    display: 'inline-block',
    lineHeight: 1,
    fontSize: 12,
    verticalAlign: 'middle',
  },
  relation: {
    position: 'relative',
    height: 100,
    transition: 'background-color 0.1s ease',
    cursor: 'pointer',
    '&:hover': {
      background: 'rgba(0, 0, 0, 0.1)',
    },
    padding: 10,
    marginBottom: 10,
  },
  relationCreation: {
    position: 'relative',
    height: 100,
    transition: 'background-color 0.1s ease',
    cursor: 'pointer',
    '&:hover': {
      background: 'rgba(0, 0, 0, 0.1)',
    },
    padding: 10,
  },
  relationCreate: {
    position: 'relative',
    height: 100,
  },
  middle: {
    margin: '0 auto',
    width: 200,
    textAlign: 'center',
    padding: 0,
    color: '#ffffff',
  },
});

export const stixCoreRelationshipCreationQuery = graphql`
  query StixCoreRelationshipCreationQuery($fromId: String!, $toId: String!) {
    stixCoreRelationships(fromId: $fromId, toId: $toId) {
      edges {
        node {
          id
          parent_types
          entity_type
          relationship_type
          description
          confidence
          start_time
          stop_time
          from {
            ... on BasicObject {
              id
              entity_type
              parent_types
            }
            ... on BasicRelationship {
              id
              entity_type
              parent_types
            }
            ... on StixCoreRelationship {
              relationship_type
            }
          }
          to {
            ... on BasicObject {
              id
              entity_type
              parent_types
            }
            ... on BasicRelationship {
              id
              entity_type
              parent_types
            }
            ... on StixCoreRelationship {
              relationship_type
            }
          }
          created_at
          updated_at
          createdBy {
            ... on Identity {
              id
              name
              entity_type
            }
          }
          objectMarking {
            edges {
              node {
                id
                definition
              }
            }
          }
        }
      }
    }
  }
`;

const stixCoreRelationshipCreationMutation = graphql`
  mutation StixCoreRelationshipCreationMutation(
    $input: StixCoreRelationshipAddInput!
  ) {
    stixCoreRelationshipAdd(input: $input) {
      id
      entity_type
      parent_types
      relationship_type
      confidence
      start_time
      stop_time
      from {
        ... on BasicObject {
          id
          entity_type
          parent_types
        }
        ... on BasicRelationship {
          id
          entity_type
          parent_types
        }
        ... on StixCoreRelationship {
          relationship_type
        }
      }
      to {
        ... on BasicObject {
          id
          entity_type
          parent_types
        }
        ... on BasicRelationship {
          id
          entity_type
          parent_types
        }
        ... on StixCoreRelationship {
          relationship_type
        }
      }
      created_at
      updated_at
      createdBy {
        ... on Identity {
          id
          name
          entity_type
        }
      }
      objectMarking {
        edges {
          node {
            id
            definition
          }
        }
      }
    }
  }
`;

const stixCoreRelationshipValidation = (t) => Yup.object().shape({
  relationship_type: Yup.string().required(t('This field is required')),
  confidence: Yup.number()
    .typeError(t('The value must be a number'))
    .integer(t('The value must be a number')),
  start_time: Yup.date()
    .nullable()
    .default(null)
    .typeError(t('The value must be a date (YYYY-MM-DD)')),
  stop_time: Yup.date()
    .nullable()
    .default(null)
    .typeError(t('The value must be a date (YYYY-MM-DD)')),
  description: Yup.string(),
});

class StixCoreRelationshipCreation extends Component {
  constructor(props) {
    super(props);
    this.state = {
      step: 0,
      existingRelations: [],
    };
  }

  onSubmit(values, { setSubmitting, resetForm }) {
    const finalValues = pipe(
      assoc('fromId', this.props.from.id),
      assoc('toId', this.props.to.id),
      assoc(
        'start_time',
        values.start_time ? parse(values.start_time).format() : null,
      ),
      assoc(
        'stop_time',
        values.stop_time ? parse(values.stop_time).format() : null,
      ),
      assoc('createdBy', values.createdBy.value),
      assoc('killChainPhases', pluck('value', values.killChainPhases)),
      assoc('objectMarking', pluck('value', values.objectMarking)),
    )(values);
    commitMutation({
      mutation: stixCoreRelationshipCreationMutation,
      variables: {
        input: finalValues,
      },
      setSubmitting,
      onCompleted: (response) => {
        setSubmitting(false);
        resetForm();
        this.props.handleResult(response.stixCoreRelationshipAdd);
        this.handleClose();
      },
    });
  }

  componentDidUpdate(prevProps) {
    if (
      this.props.open === true
      && this.props.from !== null
      && this.props.to !== null
      && (prevProps.open !== this.props.open
        || prevProps.from !== this.props.from
        || prevProps.to !== this.props.to)
    ) {
      fetchQuery(stixCoreRelationshipCreationQuery, {
        fromId: this.props.from.id,
        toId: this.props.to.id,
      })
        .toPromise()
        .then((data) => {
          this.setState({
            step:
              data.stixCoreRelationships.edges
              && data.stixCoreRelationships.edges.length > 0
                ? 1
                : 2,
            existingRelations: data.stixCoreRelationships.edges,
          });
        });
    }
  }

  handleSelectRelation(relation) {
    this.props.handleResult(relation);
    this.handleClose();
  }

  handleChangeStep() {
    this.setState({ step: 2 });
  }

  handleReverseRelation() {
    this.setState({ existingRelations: [], step: 0 }, () => this.props.handleReverseRelation());
  }

  handleClose() {
    this.setState({ existingRelations: [], step: 0 });
    this.props.handleClose();
  }

  renderForm() {
    const {
      t,
      classes,
      from,
      to,
      confidence,
      startTime,
      stopTime,
      defaultCreatedBy,
      defaultMarkingDefinitions,
    } = this.props;
    const relationshipTypes = resolveRelationsTypes(
      from.entity_type,
      to.entity_type,
    );
    // eslint-disable-next-line no-nested-ternary
    const defaultRelationshipType = head(relationshipTypes)
      ? head(relationshipTypes)
      : relationshipTypes.includes('related-to')
        ? 'related-to'
        : '';
    const defaultConfidence = confidence || 15;
    const defaultStartTime = startTime || null;
    const defaultEndTime = stopTime || null;
    const initialValues = {
      relationship_type: defaultRelationshipType,
      confidence: defaultConfidence,
      start_time: defaultStartTime,
      stop_time: defaultEndTime,
      description: '',
      killChainPhases: [],
      createdBy: defaultCreatedBy
        ? {
          label: defaultCreatedBy.name,
          value: defaultCreatedBy.id,
          type: defaultCreatedBy.entity_type,
        }
        : '',
      objectMarking: defaultMarkingDefinitions
        ? map(
          (n) => ({
            label: n.definition,
            value: n.id,
            color: n.x_opencti_color,
          }),
          defaultMarkingDefinitions,
        )
        : [],
    };
    return (
      <Formik
        enableReinitialize={true}
        initialValues={initialValues}
        validationSchema={stixCoreRelationshipValidation(t)}
        onSubmit={this.onSubmit.bind(this)}
      >
        {({ submitForm, isSubmitting, setFieldValue }) => (
          <Form>
            <div className={classes.header}>
              <IconButton
                aria-label="Close"
                className={classes.closeButton}
                onClick={this.handleClose.bind(this)}
              >
                <Close fontSize="small" />
              </IconButton>
              <Typography variant="h6">{t('Create a relationship')}</Typography>
            </div>
            <div className={classes.container}>
              <div className={classes.relationCreate}>
                <div
                  className={classes.item}
                  style={{
                    border: `2px solid ${itemColor(from.entity_type)}`,
                    top: 10,
                    left: 0,
                  }}
                >
                  <div
                    className={classes.itemHeader}
                    style={{
                      borderBottom: `1px solid ${itemColor(from.entity_type)}`,
                    }}
                  >
                    <div className={classes.icon}>
                      <ItemIcon
                        type={from.entity_type}
                        color={itemColor(from.entity_type)}
                        size="small"
                      />
                    </div>
                    <div className={classes.type}>
                      {from.relationship_type
                        ? t('Relationship')
                        : t(`entity_${from.entity_type}`)}
                    </div>
                  </div>
                  <div className={classes.content}>
                    <span className={classes.name}>
                      {from.relationship_type
                        ? t(`relationship_${from.relationship_type}`)
                        : truncate(from.name, 20)}
                    </span>
                  </div>
                </div>
                <div className={classes.middle} style={{ paddingTop: 25 }}>
                  <ArrowRightAlt fontSize="large" />
                  <br />
                  <Button
                    variant="outlined"
                    onClick={this.handleReverseRelation.bind(this)}
                    color="secondary"
                    size="small"
                  >
                    {t('Reverse')}
                  </Button>
                </div>
                <div
                  className={classes.item}
                  style={{
                    border: `2px solid ${itemColor(to.entity_type)}`,
                    top: 10,
                    right: 0,
                  }}
                >
                  <div
                    className={classes.itemHeader}
                    style={{
                      borderBottom: `1px solid ${itemColor(to.entity_type)}`,
                    }}
                  >
                    <div className={classes.icon}>
                      <ItemIcon
                        type={to.entity_type}
                        color={itemColor(to.entity_type)}
                        size="small"
                      />
                    </div>
                    <div className={classes.type}>
                      {to.relationship_type
                        ? t('Relationship')
                        : t(`entity_${to.entity_type}`)}
                    </div>
                  </div>
                  <div className={classes.content}>
                    <span className={classes.name}>
                      {to.relationship_type
                        ? t(`relationship_${to.relationship_type}`)
                        : truncate(to.name, 20)}
                    </span>
                  </div>
                </div>
              </div>
              <Field
                component={SelectField}
                name="relationship_type"
                label={t('Relationship type')}
                fullWidth={true}
                containerstyle={{ marginTop: 20, width: '100%' }}
              >
                {map(
                  (type) => (
                    <MenuItem key={type} value={type}>
                      {t(`relationship_${type}`)}
                    </MenuItem>
                  ),
                  relationshipTypes,
                )}
              </Field>
              <ConfidenceField
                name="confidence"
                label={t('Confidence level')}
                fullWidth={true}
                containerstyle={{ marginTop: 20, width: '100%' }}
              />
              <Field
                component={DatePickerField}
                name="start_time"
                label={t('Start time')}
                invalidDateMessage={t('The value must be a date (YYYY-MM-DD)')}
                fullWidth={true}
                style={{ marginTop: 20 }}
              />
              <Field
                component={DatePickerField}
                name="stop_time"
                label={t('Stop time')}
                invalidDateMessage={t('The value must be a date (YYYY-MM-DD)')}
                fullWidth={true}
                style={{ marginTop: 20 }}
              />
              <Field
                component={MarkDownField}
                name="description"
                label={t('Description')}
                fullWidth={true}
                multiline={true}
                rows="4"
                style={{ marginTop: 20 }}
              />
              <KillChainPhasesField
                name="killChainPhases"
                style={{ marginTop: 20, width: '100%' }}
              />
              <CreatedByField
                name="createdBy"
                style={{ marginTop: 20, width: '100%' }}
                setFieldValue={setFieldValue}
              />
              <ObjectMarkingField
                name="objectMarking"
                style={{ marginTop: 20, width: '100%' }}
              />
              <div className={classes.buttons}>
                <Button
                  variant="contained"
                  onClick={this.handleClose.bind(this)}
                  disabled={isSubmitting}
                  classes={{ root: classes.button }}
                >
                  {t('Cancel')}
                </Button>
                <Button
                  variant="contained"
                  color="primary"
                  onClick={submitForm}
                  disabled={isSubmitting}
                  classes={{ root: classes.button }}
                >
                  {t('Create')}
                </Button>
              </div>
            </div>
          </Form>
        )}
      </Formik>
    );
  }

  renderSelectRelation() {
    const {
      nsd, t, classes, from, to,
    } = this.props;
    const { existingRelations } = this.state;

    return (
      <div>
        <div className={classes.header}>
          <IconButton
            aria-label="Close"
            className={classes.closeButton}
            onClick={this.handleClose.bind(this)}
          >
            <Close fontSize="small" />
          </IconButton>
          <Typography variant="h6">{t('Select a relationship')}</Typography>
        </div>
        <div className={classes.container}>
          {existingRelations.map((relation) => (
            <div
              key={relation.node.id}
              className={classes.relation}
              onClick={this.handleSelectRelation.bind(this, relation.node)}
            >
              <div
                className={classes.item}
                style={{
                  border: `2px solid ${itemColor(from.entity_type)}`,
                  top: 10,
                  left: 0,
                }}
              >
                <div
                  className={classes.itemHeader}
                  style={{
                    borderBottom: `1px solid ${itemColor(from.entity_type)}`,
                  }}
                >
                  <div className={classes.icon}>
                    <ItemIcon
                      type={from.entity_type}
                      color={itemColor(from.entity_type)}
                      size="small"
                    />
                  </div>
                  <div className={classes.type}>
                    {from.relationship_type
                      ? t('Relationship')
                      : t(`entity_${from.entity_type}`)}
                  </div>
                </div>
                <div className={classes.content}>
                  <span className={classes.name}>{from.name}</span>
                </div>
              </div>
              <div className={classes.middle}>
                <ArrowRightAlt fontSize="small" />
                <br />
                <Tooltip
                  title={relation.node.description}
                  aria-label="Description"
                  placement="top"
                >
                  <div
                    style={{
                      padding: '5px 8px 5px 8px',
                      backgroundColor: '#14262c',
                      color: '#ffffff',
                      fontSize: 12,
                      display: 'inline-block',
                    }}
                  >
                    {t(`relationship_${relation.node.relationship_type}`)}
                    <br />
                    {t('First obs.')} {nsd(relation.node.start_time)}
                    <br />
                    {t('Last obs.')} {nsd(relation.node.stop_time)}
                  </div>
                </Tooltip>
              </div>
              <div
                className={classes.item}
                style={{
                  border: `2px solid ${itemColor(to.entity_type)}`,
                  top: 10,
                  right: 0,
                }}
              >
                <div
                  className={classes.itemHeader}
                  style={{
                    borderBottom: `1px solid ${itemColor(to.entity_type)}`,
                  }}
                >
                  <div className={classes.icon}>
                    <ItemIcon
                      type={to.entity_type}
                      color={itemColor(to.entity_type)}
                      size="small"
                    />
                  </div>
                  <div className={classes.type}>
                    {to.relationship_type
                      ? t('Relationship')
                      : t(`entity_${to.entity_type}`)}
                  </div>
                </div>
                <div className={classes.content}>
                  <span className={classes.name}>{to.name}</span>
                </div>
              </div>
              <div className="clearfix" />
            </div>
          ))}
          <div
            className={classes.relationCreation}
            onClick={this.handleChangeStep.bind(this)}
          >
            <div
              className={classes.item}
              style={{
                backgroundColor: '#607d8b',
                top: 10,
                left: 0,
              }}
            >
              <div
                className={classes.itemHeader}
                style={{
                  borderBottom: '1px solid #ffffff',
                }}
              >
                <div className={classes.icon}>
                  <ItemIcon
                    type={from.entity_type}
                    color="#263238"
                    size="small"
                  />
                </div>
                <div className={classes.type}>
                  {t(`entity_${from.entity_type}`)}
                </div>
              </div>
              <div className={classes.content}>
                <span className={classes.name}>{from.name}</span>
              </div>
            </div>
            <div className={classes.middle} style={{ paddingTop: 15 }}>
              <ArrowRightAlt fontSize="small" />
              <br />
              <div
                style={{
                  padding: '5px 8px 5px 8px',
                  backgroundColor: '#607d8b',
                  color: '#ffffff',
                  fontSize: 12,
                  display: 'inline-block',
                }}
              >
                {t('Create a relationship')}
              </div>
            </div>
            <div
              className={classes.item}
              style={{
                backgroundColor: '#607d8b',
                top: 10,
                right: 0,
              }}
            >
              <div
                className={classes.itemHeader}
                style={{
                  borderBottom: '1px solid #ffffff',
                }}
              >
                <div className={classes.icon}>
                  <ItemIcon
                    type={to.entity_type}
                    color="#263238"
                    size="small"
                  />
                </div>
                <div className={classes.type}>
                  {t(`entity_${to.entity_type}`)}
                </div>
              </div>
              <div className={classes.content}>
                <span className={classes.name}>{to.name}</span>
              </div>
            </div>
            <div className="clearfix" />
          </div>
        </div>
      </div>
    );
  }

  // eslint-disable-next-line
  renderLoader() {
    return (
      <div style={{ display: 'table', height: '100%', width: '100%' }}>
        <span
          style={{
            display: 'table-cell',
            verticalAlign: 'middle',
            textAlign: 'center',
          }}
        >
          <CircularProgress size={80} thickness={2} />
        </span>
      </div>
    );
  }

  render() {
    const {
      open, from, to, classes,
    } = this.props;
    const { step } = this.state;
    return (
      <Drawer
        open={open}
        anchor="right"
        classes={{ paper: classes.drawerPaper }}
        onClose={this.handleClose.bind(this)}
      >
        {step === 0 || step === undefined || from === null || to === null
          ? this.renderLoader()
          : ''}
        {step === 1 ? this.renderSelectRelation() : ''}
        {step === 2 ? this.renderForm() : ''}
      </Drawer>
    );
  }
}

StixCoreRelationshipCreation.propTypes = {
  open: PropTypes.bool,
  from: PropTypes.object,
  to: PropTypes.object,
  handleResult: PropTypes.func,
  classes: PropTypes.object,
  t: PropTypes.func,
  nsd: PropTypes.func,
  startTime: PropTypes.string,
  stopTime: PropTypes.string,
  confidence: PropTypes.number,
  defaultCreatedBy: PropTypes.object,
  defaultMarkingDefinitions: PropTypes.object,
  handleClose: PropTypes.func,
  handleReverseRelation: PropTypes.func,
};

export default compose(
  inject18n,
  withStyles(styles),
)(StixCoreRelationshipCreation);
