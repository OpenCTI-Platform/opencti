import React, { useEffect, useRef, useState } from 'react';
import { graphql } from 'react-relay';
import * as R from 'ramda';
import Drawer from '@mui/material/Drawer';
import Typography from '@mui/material/Typography';
import IconButton from '@mui/material/IconButton';
import Tooltip from '@mui/material/Tooltip';
import CircularProgress from '@mui/material/CircularProgress';
import { ArrowRightAlt, Close } from '@mui/icons-material';
import { useTheme } from '@mui/styles';
import makeStyles from '@mui/styles/makeStyles';
import { commitMutation, fetchQuery } from '../../../../relay/environment';
import { itemColor } from '../../../../utils/Colors';
import { formatDate } from '../../../../utils/Time';
import ItemIcon from '../../../../components/ItemIcon';
import { truncate } from '../../../../utils/String';
import StixCoreRelationshipCreationForm from './StixCoreRelationshipCreationForm';
import { resolveRelationsTypes } from '../../../../utils/Relation';
import { UserContext } from '../../../../utils/hooks/useAuth';
import ProgressBar from '../../../../components/ProgressBar';
import { useFormatter } from '../../../../components/i18n';

const useStyles = makeStyles((theme) => ({
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
}));

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
        id
        definition_type
        definition
        x_opencti_order
        x_opencti_color
      }
    }
  }
`;

const commitWithPromise = (values) => new Promise((resolve, reject) => {
  commitMutation({
    mutation: stixCoreRelationshipCreationMutation,
    variables: {
      input: values,
    },
    onError: (error) => {
      reject(error);
    },
    onCompleted: (response) => {
      resolve(response.stixCoreRelationshipAdd);
    },
  });
});

const StixCoreRelationshipCreation = ({
  onClose,
  onReverseRelation,
  fromObjects,
  toObjects,
  handleResult,
  confidence,
  startTime,
  stopTime,
  defaultCreatedBy,
  defaultMarkingDefinitions,
  open,
}) => {
  const classes = useStyles();
  const { t_i18n, fsd } = useFormatter();
  const theme = useTheme();

  const [step, setStep] = useState(0);
  const [existingRelations, setExistingRelations] = useState([]);
  const [displayProgress, setDisplayProgress] = useState(false);
  const [progress, setProgress] = useState(0);
  const prevProps = useRef({ open, fromObjects, toObjects });

  useEffect(() => {
    const prev = prevProps.current;
    const openChanged = prev.open !== open;
    const fromChanged = prev.fromObjects?.[0] !== fromObjects?.[0];
    const toChanged = prev.toObjects?.[0] !== toObjects?.[0];

    const shouldFetch = open === true
      && fromObjects !== null
      && toObjects !== null
      && (openChanged || fromChanged || toChanged);

    if (shouldFetch) {
      if (
        fromObjects.length === 1
        && toObjects.length === 1
      ) {
        fetchQuery(stixCoreRelationshipCreationQuery, {
          fromId: fromObjects[0].id,
          toId: toObjects[0].id,
        })
          .toPromise()
          .then((data) => {
            const newStep = data.stixCoreRelationships.edges
            && data.stixCoreRelationships.edges.length > 0
              ? 1
              : 2;
            setStep(newStep);
            setExistingRelations(data.stixCoreRelationships.edges);
          });
      } else {
        setStep(2);
        setExistingRelations([]);
      }
    }
    prevProps.current = { open, fromObjects, toObjects };
  }, [open, fromObjects, toObjects]);

  const handleClose = () => {
    setExistingRelations([]);
    setStep(0);
    onClose();
  };

  const handleCloseProgressBar = () => {
    setDisplayProgress(false);
  };

  const onSubmit = async (values, { resetForm }) => {
    setDisplayProgress(true);
    handleClose();
    resetForm();
    let latestResponse;
    let current = 1;
    const total = fromObjects.length * toObjects.length;
    for (const fromObject of fromObjects) {
      for (const toObject of toObjects) {
        const finalValues = R.pipe(
          R.assoc('confidence', parseInt(values.confidence, 10)),
          R.assoc('fromId', fromObject.id),
          R.assoc('toId', toObject.id),
          R.assoc('start_time', formatDate(values.start_time)),
          R.assoc('stop_time', formatDate(values.stop_time)),
          R.assoc('killChainPhases', R.pluck('value', values.killChainPhases)),
          R.assoc('createdBy', values.createdBy?.value),
          R.assoc('objectMarking', R.pluck('value', values.objectMarking)),
          R.assoc(
            'externalReferences',
            R.pluck('value', values.externalReferences),
          ),
        )(values);
        // eslint-disable-next-line no-await-in-loop
        latestResponse = await commitWithPromise(finalValues);
        const lastObject = current === total;
        handleResult(latestResponse, !lastObject);
        current += 1;
        setProgress(Math.round((current * 100) / total));
      }
    }
    setDisplayProgress(false);
    setProgress(0);
  };

  const handleSelectRelation = (relation) => {
    handleResult(relation);
    handleClose();
  };

  const handleChangeStep = () => {
    setStep(2);
  };

  const handleReverseRelation = () => {
    setExistingRelations([]);
    setStep(2);
    onReverseRelation();
  };

  const renderForm = () => {
    return (
      <UserContext.Consumer>
        {({ schema }) => {
          const relationshipTypes = R.uniq(resolveRelationsTypes(
            fromObjects[0].entity_type,
            toObjects[0].entity_type,
            schema.schemaRelationsTypesMapping,
          ));
          return (
            <>
              <div className={classes.header}>
                <IconButton
                  aria-label="Close"
                  className={classes.closeButton}
                  onClick={handleClose}
                  size="large"
                >
                  <Close fontSize="small" color="primary" />
                </IconButton>
                <Typography variant="h6">{t_i18n('Create a relationship')}</Typography>
              </div>
              <StixCoreRelationshipCreationForm
                fromEntities={fromObjects}
                toEntities={toObjects}
                relationshipTypes={relationshipTypes}
                handleReverseRelation={handleReverseRelation}
                onSubmit={onSubmit}
                handleClose={handleClose}
                defaultConfidence={confidence}
                defaultStartTime={startTime}
                defaultStopTime={stopTime}
                defaultCreatedBy={defaultCreatedBy}
                defaultMarkingDefinitions={defaultMarkingDefinitions}
              />
            </>
          );
        }}
      </UserContext.Consumer>
    );
  };

  const renderSelectRelation = () => {
    return (
      <div>
        <div className={classes.header}>
          <IconButton
            aria-label="Close"
            className={classes.closeButton}
            onClick={handleClose}
            size="large"
          >
            <Close fontSize="small" color="primary" />
          </IconButton>
          <Typography variant="h6">{t_i18n('Select a relationship')}</Typography>
        </div>
        <div className={classes.container}>
          {existingRelations.map((relation) => (
            <div
              key={relation.node.id}
              className={classes.relation}
              onClick={() => handleSelectRelation(relation.node)}
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
                      ? t_i18n('Relationship')
                      : t_i18n(`entity_${fromObjects[0].entity_type}`)}
                  </div>
                </div>
                <div className={classes.content}>
                  <span className={classes.name}>
                    {fromObjects.length > 1 ? (
                      <em>{t_i18n('Multiple entities selected')}</em>
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
                    {t_i18n(`relationship_${relation.node.relationship_type}`)}
                    <br />
                    {t_i18n('Start time')} {fsd(relation.node.start_time)}
                    <br />
                    {t_i18n('Stop time')} {fsd(relation.node.stop_time)}
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
                      ? t_i18n('Relationship')
                      : t_i18n(`entity_${toObjects[0].entity_type}`)}
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
            onClick={handleChangeStep}
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
                  {t_i18n(`entity_${fromObjects[0].entity_type}`)}
                </div>
              </div>
              <div className={classes.content}>
                <span className={classes.name}>
                  {fromObjects.length > 1 ? (
                    <em>{t_i18n('Multiple entities selected')}</em>
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
                {t_i18n('Create a relationship')}
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
                  {t_i18n(`entity_${toObjects[0].entity_type}`)}
                </div>
              </div>
              <div className={classes.content}>
                <span className={classes.name}>
                  {toObjects.length > 1 ? (
                    <em>{t_i18n('Multiple entities selected')}</em>
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
  };

  // eslint-disable-next-line
  const renderLoader = () => {
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
  };

  return (
    <>
      <Drawer
        open={open}
        anchor="right"
        elevation={1}
        sx={{ zIndex: 1202 }}
        classes={{ paper: classes.drawerPaper }}
        onClose={handleClose}
      >
        {step === 0
        || step === undefined
        || fromObjects === null
        || toObjects === null
          ? renderLoader()
          : ''}
        {step === 1 ? renderSelectRelation() : ''}
        {step === 2 ? renderForm() : ''}
      </Drawer>
      <ProgressBar
        title={t_i18n('Create multiple relationships')}
        open={displayProgress}
        value={progress}
        onClose={handleCloseProgressBar}
        variant='determinate'
      />
    </>
  );
};

export default StixCoreRelationshipCreation;
