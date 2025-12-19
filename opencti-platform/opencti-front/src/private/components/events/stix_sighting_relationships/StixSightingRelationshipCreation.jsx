import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { graphql } from 'react-relay';
import * as R from 'ramda';
import withTheme from '@mui/styles/withTheme';
import withStyles from '@mui/styles/withStyles';
import Drawer from '@mui/material/Drawer';
import Typography from '@mui/material/Typography';
import IconButton from '@common/button/IconButton';
import Tooltip from '@mui/material/Tooltip';
import CircularProgress from '@mui/material/CircularProgress';
import { ArrowRightAlt, Close } from '@mui/icons-material';
import { MESSAGING$, commitMutation, fetchQuery } from '../../../../relay/environment';
import inject18n, { isNone } from '../../../../components/i18n';
import { itemColor } from '../../../../utils/Colors';
import { formatDate } from '../../../../utils/Time';
import ItemIcon from '../../../../components/ItemIcon';
import { truncate } from '../../../../utils/String';
import { getMainRepresentative } from '../../../../utils/defaultRepresentatives';
import StixSightingRelationshipCreationForm from './StixSightingRelationshipCreationForm';

const styles = (theme) => ({
  drawerPaper: {
    minHeight: '100vh',
    width: '50%',
    padding: 0,
  },
  createButton: {
    position: 'fixed',
    bottom: 30,
    right: 30,
    zIndex: 2000,
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

export const stixSightingRelationshipCreationQuery = graphql`
  query StixSightingRelationshipCreationQuery(
    $fromId: StixRef!
    $toId: StixRef!
  ) {
    stixSightingRelationships(fromId: $fromId, toId: $toId) {
      edges {
        node {
          id
          parent_types
          entity_type
          description
          confidence
          first_seen
          last_seen
          attribute_count
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

const stixSightingRelationshipCreationMutation = graphql`
  mutation StixSightingRelationshipCreationMutation(
    $input: StixSightingRelationshipAddInput!
  ) {
    stixSightingRelationshipAdd(input: $input) {
      id
      entity_type
      parent_types
      confidence
      first_seen
      last_seen
      attribute_count
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
        id
        definition_type
        definition
        x_opencti_order
        x_opencti_color
      }
    }
  }
`;

class StixSightingRelationshipCreation extends Component {
  constructor(props) {
    super(props);
    this.state = {
      step: 0,
      existingSightings: [],
    };
  }

  onSubmit(values, { setSubmitting, resetForm }) {
    const { t } = this.props;
    R.forEach((fromObject) => {
      R.forEach((toObject) => {
        const finalValues = R.pipe(
          R.assoc('confidence', parseInt(values.confidence, 10)),
          R.assoc('attribute_count', parseInt(values.attribute_count, 10)),
          R.assoc('fromId', fromObject.id),
          R.assoc('toId', toObject.id),
          R.assoc('first_seen', formatDate(values.first_seen)),
          R.assoc('last_seen', formatDate(values.last_seen)),
          R.assoc('createdBy', values.createdBy?.value),
          R.assoc('objectMarking', R.pluck('value', values.objectMarking)),
          R.assoc('externalReferences', R.pluck('value', values.externalReferences)),
        )(values);
        commitMutation({
          mutation: stixSightingRelationshipCreationMutation,
          variables: {
            input: finalValues,
          },
          setSubmitting,
          // TODO: Remove onError when functional component; error toast handled by useApiMutation
          onError: (error) => {
            MESSAGING$.notifyError(`${error}`);
          },
          onCompleted: (response) => {
            this.props.handleResult(response.stixSightingRelationshipAdd);
            // TODO: Remove success toast when functional component
            MESSAGING$.notifySuccess(`${t('entity_Sighting')} ${t('successfully created')}`);
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
        fetchQuery(stixSightingRelationshipCreationQuery, {
          fromId: this.props.fromObjects[0].id,
          toId: this.props.toObjects[0].id,
        })
          .toPromise()
          .then((data) => {
            this.setState({
              step:
                data.stixSightingRelationships.edges
                && data.stixSightingRelationships.edges.length > 0
                  ? 1
                  : 2,
              existingSightings: data.stixSightingRelationships.edges,
            });
          });
      } else {
        this.setState({ step: 2, existingRelations: [] });
      }
    }
  }

  handleSelectSighting(sighting) {
    this.props.handleResult(sighting);
    this.handleClose();
  }

  handleChangeStep() {
    this.setState({ step: 2 });
  }

  handleReverseSighting() {
    this.setState({ existingSightings: [], step: 0 }, () => this.props.handleReverseSighting());
  }

  handleClose() {
    this.setState({ existingSightings: [], step: 0 });
    this.props.handleClose();
  }

  renderForm() {
    const {
      t,
      classes,
      fromObjects,
      toObjects,
      confidence,
      firstSeen,
      lastSeen,
      defaultCreatedBy,
      defaultMarkingDefinitions,
    } = this.props;
    const defaultConfidence = confidence || 15;
    const defaultFirstSeen = !isNone(firstSeen) ? firstSeen : null;
    const defaultLastSeen = !isNone(lastSeen) ? lastSeen : null;
    return (
      <>
        <div className={classes.header}>
          <IconButton
            aria-label="Close"
            className={classes.closeButton}
            onClick={this.handleClose.bind(this)}
          >
            <Close fontSize="small" color="primary" />
          </IconButton>
          <Typography variant="h6">{t('Create a sighting')}</Typography>
        </div>
        <StixSightingRelationshipCreationForm
          fromEntities={fromObjects}
          toEntities={toObjects}
          handleReverseRelation={this.handleReverseSighting.bind(this)}
          onSubmit={this.onSubmit.bind(this)}
          handleClose={this.handleClose.bind(this)}
          defaultConfidence={defaultConfidence}
          defaultFirstSeen={defaultFirstSeen}
          defaultLastSeen={defaultLastSeen}
          defaultCreatedBy={defaultCreatedBy}
          defaultMarkingDefinitions={defaultMarkingDefinitions}
        />
      </>
    );
  }

  renderSelectSighting() {
    const { fsd, t, classes, fromObjects, toObjects, theme } = this.props;
    const { existingSightings } = this.state;
    return (
      <div>
        <div className={classes.header}>
          <IconButton
            aria-label="Close"
            className={classes.closeButton}
            onClick={this.handleClose.bind(this)}
          >
            <Close fontSize="small" color="primary" />
          </IconButton>
          <Typography variant="h6">{t('Select a sighting')}</Typography>
        </div>
        <div className={classes.container}>
          {existingSightings.map((sighting) => (
            <div
              key={sighting.node.id}
              className={classes.relation}
              onClick={this.handleSelectSighting.bind(this, sighting.node)}
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
                  title={sighting.node.description}
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
                    {t('sig')}
                    <br />
                    {t('First obs.')} {fsd(sighting.node.first_seen)}
                    <br />
                    {t('Last obs.')} {fsd(sighting.node.last_seen)}
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
                    {truncate(getMainRepresentative(toObjects[0]), 20)}
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
                    truncate(getMainRepresentative(fromObjects[0]))
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
                {t('Create a sighting')}
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
        {step === 1 ? this.renderSelectSighting() : ''}
        {step === 2 ? this.renderForm() : ''}
      </Drawer>
    );
  }
}

StixSightingRelationshipCreation.propTypes = {
  open: PropTypes.bool,
  fromObjects: PropTypes.array,
  toObjects: PropTypes.array,
  handleResult: PropTypes.func,
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
  fsd: PropTypes.func,
  firstSeen: PropTypes.string,
  lastSeen: PropTypes.string,
  confidence: PropTypes.number,
  defaultCreatedBy: PropTypes.oneOfType([PropTypes.object, PropTypes.string]),
  defaultMarkingDefinitions: PropTypes.array,
  handleClose: PropTypes.func,
  handleReverseSighting: PropTypes.func,
};

export default R.compose(
  inject18n,
  withTheme,
  withStyles(styles),
)(StixSightingRelationshipCreation);
