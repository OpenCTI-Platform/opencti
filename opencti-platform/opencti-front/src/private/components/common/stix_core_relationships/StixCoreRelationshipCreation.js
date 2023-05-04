import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { graphql } from 'react-relay';
import * as R from 'ramda';
import withTheme from '@mui/styles/withTheme';
import withStyles from '@mui/styles/withStyles';
import Drawer from '@mui/material/Drawer';
import Typography from '@mui/material/Typography';
import IconButton from '@mui/material/IconButton';
import Tooltip from '@mui/material/Tooltip';
import CircularProgress from '@mui/material/CircularProgress';
import { ArrowRightAlt, Close } from '@mui/icons-material';
import { commitMutation, fetchQuery } from '../../../../relay/environment';
import inject18n from '../../../../components/i18n';
import { itemColor } from '../../../../utils/Colors';
import { formatDate } from '../../../../utils/Time';
import { resolveRelationsTypes } from '../../../../utils/Relation';
import ItemIcon from '../../../../components/ItemIcon';
import { truncate } from '../../../../utils/String';
import StixCoreRelationshipCreationForm from './StixCoreRelationshipCreationForm';

const styles = (theme) => ({
  drawerPaper: {
    minHeight: '100vh',
    width: '50%',
    padding: 0,
  },
  header: {
    backgroundColor: theme.palette.background.nav,
    padding: '20px 20px 20px 60px',
  },
  closeButton: {
    position: 'absolute',
    top: 12,
    left: 5,
    color: 'inherit',
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
    color: theme.palette.text.primary,
    fontSize: 11,
  },
  content: {
    width: '100%',
    height: 40,
    maxHeight: 40,
    lineHeight: '40px',
    color: theme.palette.text.primary,
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
  middle: {
    margin: '0 auto',
    width: 200,
    textAlign: 'center',
    padding: 0,
    color: theme.palette.text.primary,
  },
});

export const stixCoreRelationshipCreationQuery = graphql`
  query StixCoreRelationshipCreationQuery(
    $fromId: [String]!
    $toId: [String]!
  ) {
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
          created
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
              created
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
              created
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
                definition_type
                definition
                x_opencti_order
                x_opencti_color
              }
            }
          }
        }
      }
    }
  }
`;

export const stixCoreRelationshipCreationMutation = graphql`
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

class StixCoreRelationshipCreation extends Component {
  constructor(props) {
    super(props);
    this.state = {
      step: 0,
      existingRelations: [],
    };
  }

  onSubmit(values, { setSubmitting, resetForm }) {
    R.forEach((fromObject) => {
      R.forEach((toObject) => {
        const finalValues = R.pipe(
          R.assoc('confidence', parseInt(values.confidence, 10)),
          R.assoc('fromId', fromObject.id),
          R.assoc('toId', toObject.id),
          R.assoc('start_time', formatDate(values.start_time)),
          R.assoc('stop_time', formatDate(values.stop_time)),
          R.assoc('createdBy', values.createdBy?.value),
          R.assoc('killChainPhases', R.pluck('value', values.killChainPhases)),
          R.assoc('objectMarking', R.pluck('value', values.objectMarking)),
          R.assoc(
            'externalReferences',
            R.pluck('value', values.externalReferences),
          ),
        )(values);
        commitMutation({
          mutation: stixCoreRelationshipCreationMutation,
          variables: {
            input: finalValues,
          },
          setSubmitting,
          onCompleted: (response) => {
            this.props.handleResult(response.stixCoreRelationshipAdd);
          },
        });
      }, this.props.toObjects);
    }, this.props.fromObjects);
    setSubmitting(false);
    resetForm();
    this.handleClose();
  }

  componentDidUpdate(prevProps) {
    if (
      this.props.open === true
      && this.props.fromObjects !== null
      && this.props.toObjects !== null
      && (prevProps.open !== this.props.open
        || prevProps.fromObjects[0] !== this.props.fromObjects[0]
        || prevProps.toObjects[0] !== this.props.toObjects[0])
    ) {
      if (
        this.props.fromObjects.length === 1
        && this.props.toObjects.length === 1
      ) {
        fetchQuery(stixCoreRelationshipCreationQuery, {
          fromId: this.props.fromObjects[0].id,
          toId: this.props.toObjects[0].id,
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
      } else {
        this.setState({ step: 2, existingRelations: [] });
      }
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
      fromObjects,
      toObjects,
      confidence,
      startTime,
      stopTime,
      defaultCreatedBy,
      defaultMarkingDefinitions,
    } = this.props;
    const relationshipTypes = resolveRelationsTypes(
      fromObjects[0].entity_type,
      toObjects[0].entity_type,
    );
    return (
      <>
        <div className={classes.header}>
          <IconButton
            aria-label="Close"
            className={classes.closeButton}
            onClick={this.handleClose.bind(this)}
            size="large"
          >
            <Close fontSize="small" color="primary" />
          </IconButton>
          <Typography variant="h6">{t('Create a relationship')}</Typography>
        </div>
      <StixCoreRelationshipCreationForm
        fromEntities={fromObjects}
        toEntities={toObjects}
        relationshipTypes={relationshipTypes}
        handleReverseRelation={this.handleReverseRelation.bind(this)}
        onSubmit={this.onSubmit.bind(this)}
        handleClose={this.handleClose.bind(this)}
        defaultConfidence={confidence}
        defaultStartTime={startTime}
        defaultStopTime={stopTime}
        defaultCreatedBy={defaultCreatedBy}
        defaultMarkingDefinitions={defaultMarkingDefinitions}
      />
      </>
    );
  }

  renderSelectRelation() {
    const { fsd, t, classes, fromObjects, toObjects, theme } = this.props;
    const { existingRelations } = this.state;
    return (
      <div>
        <div className={classes.header}>
          <IconButton
            aria-label="Close"
            className={classes.closeButton}
            onClick={this.handleClose.bind(this)}
            size="large"
          >
            <Close fontSize="small" color="primary" />
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
                  border: `2px solid ${itemColor(fromObjects[0].entity_type)}`,
                  top: 10,
                  left: 10,
                }}
              >
                <div
                  className={classes.itemHeader}
                  style={{
                    borderBottom: `1px solid ${itemColor(
                      fromObjects[0].entity_type,
                    )}`,
                  }}
                >
                  <div className={classes.icon}>
                    <ItemIcon
                      type={fromObjects[0].entity_type}
                      color={itemColor(fromObjects[0].entity_type)}
                      size="small"
                    />
                  </div>
                  <div className={classes.type}>
                    {fromObjects[0].relationship_type
                      ? t('Relationship')
                      : t(`entity_${fromObjects[0].entity_type}`)}
                  </div>
                </div>
                <div className={classes.content}>
                  <span className={classes.name}>
                    {fromObjects.length > 1 ? (
                      <em>{t('Multiple entities selected')}</em>
                    ) : (
                      truncate(fromObjects[0].name, 20)
                    )}
                  </span>
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
                      backgroundColor: theme.palette.background.accent,
                      color: theme.palette.text.primary,
                      fontSize: 12,
                      display: 'inline-block',
                    }}
                  >
                    {t(`relationship_${relation.node.relationship_type}`)}
                    <br />
                    {t('First obs.')} {fsd(relation.node.start_time)}
                    <br />
                    {t('Last obs.')} {fsd(relation.node.stop_time)}
                  </div>
                </Tooltip>
              </div>
              <div
                className={classes.item}
                style={{
                  border: `2px solid ${itemColor(toObjects[0].entity_type)}`,
                  top: 10,
                  right: 10,
                }}
              >
                <div
                  className={classes.itemHeader}
                  style={{
                    borderBottom: `1px solid ${itemColor(
                      toObjects[0].entity_type,
                    )}`,
                  }}
                >
                  <div className={classes.icon}>
                    <ItemIcon
                      type={toObjects[0].entity_type}
                      color={itemColor(toObjects[0].entity_type)}
                      size="small"
                    />
                  </div>
                  <div className={classes.type}>
                    {toObjects[0].relationship_type
                      ? t('Relationship')
                      : t(`entity_${toObjects[0].entity_type}`)}
                  </div>
                </div>
                <div className={classes.content}>
                  <span className={classes.name}>
                    {truncate(toObjects[0].name, 20)}
                  </span>
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
                backgroundColor: theme.palette.background.accent,
                top: 10,
                left: 10,
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
                    type={fromObjects[0].entity_type}
                    color="#263238"
                    size="small"
                  />
                </div>
                <div className={classes.type}>
                  {t(`entity_${fromObjects[0].entity_type}`)}
                </div>
              </div>
              <div className={classes.content}>
                <span className={classes.name}>
                  {fromObjects.length > 1 ? (
                    <em>{t('Multiple entities selected')}</em>
                  ) : (
                    truncate(fromObjects[0].name)
                  )}
                </span>
              </div>
            </div>
            <div className={classes.middle} style={{ paddingTop: 15 }}>
              <ArrowRightAlt fontSize="small" />
              <br />
              <div
                style={{
                  padding: '5px 8px 5px 8px',
                  backgroundColor: theme.palette.background.accent,
                  color: theme.palette.text.primary,
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
                backgroundColor: theme.palette.background.accent,
                top: 10,
                right: 10,
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
                    type={toObjects[0].entity_type}
                    color="#263238"
                    size="small"
                  />
                </div>
                <div className={classes.type}>
                  {t(`entity_${toObjects[0].entity_type}`)}
                </div>
              </div>
              <div className={classes.content}>
                <span className={classes.name}>
                  {toObjects.length > 1 ? (
                    <em>{t('Multiple entities selected')}</em>
                  ) : (
                    truncate(toObjects[0].name, 20)
                  )}
                </span>
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
    const { open, fromObject, toObjects, classes } = this.props;
    const { step } = this.state;
    return (
      <Drawer
        open={open}
        anchor="right"
        elevation={1}
        sx={{ zIndex: 1202 }}
        classes={{ paper: classes.drawerPaper }}
        onClose={this.handleClose.bind(this)}
      >
        {step === 0
        || step === undefined
        || fromObject === null
        || toObjects === null
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
  fromObjects: PropTypes.object,
  toObjects: PropTypes.array,
  handleResult: PropTypes.func,
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
  fsd: PropTypes.func,
  startTime: PropTypes.string,
  stopTime: PropTypes.string,
  confidence: PropTypes.number,
  defaultCreatedBy: PropTypes.object,
  defaultMarkingDefinitions: PropTypes.object,
  handleClose: PropTypes.func,
  handleReverseRelation: PropTypes.func,
};

export default R.compose(
  inject18n,
  withTheme,
  withStyles(styles),
)(StixCoreRelationshipCreation);
