import React, { useEffect, useRef, useState } from 'react';
import { graphql } from 'react-relay';
import * as R from 'ramda';
import Drawer from '@mui/material/Drawer';
import Typography from '@mui/material/Typography';
import IconButton from '@common/button/IconButton';
import Tooltip from '@mui/material/Tooltip';
import CircularProgress from '@mui/material/CircularProgress';
import { ArrowRightAlt, Close } from '@mui/icons-material';
import { useTheme } from '@mui/styles';
import makeStyles from '@mui/styles/makeStyles';
import { StixCoreRelationshipCreationQuery$data } from '@components/common/stix_core_relationships/__generated__/StixCoreRelationshipCreationQuery.graphql';
import { FormikConfig } from 'formik/dist/types';
import { StixCoreRelationshipCreationMutation } from '@components/common/stix_core_relationships/__generated__/StixCoreRelationshipCreationMutation.graphql';
import { fetchQuery } from '../../../../relay/environment';
import { itemColor } from '../../../../utils/Colors';
import { formatDate } from '../../../../utils/Time';
import ItemIcon from '../../../../components/ItemIcon';
import { truncate } from '../../../../utils/String';
import StixCoreRelationshipCreationForm from './StixCoreRelationshipCreationForm';
import { resolveRelationsTypes } from '../../../../utils/Relation';
import { UserContext } from '../../../../utils/hooks/useAuth';
import ProgressBar from '../../../../components/ProgressBar';
import { useFormatter } from '../../../../components/i18n';
import { GraphLink, GraphNode } from '../../../../components/graph/graph.types';
import { ObjectToParse } from '../../../../components/graph/utils/useGraphParser';
import { FieldOption } from '../../../../utils/field';
import type { Theme } from '../../../../components/Theme';
import useApiMutation from '../../../../utils/hooks/useApiMutation';

const useStyles = makeStyles<Theme>((theme) => ({
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
    color: theme.palette.text?.primary,
    fontSize: 11,
  },
  content: {
    width: '100%',
    height: 40,
    maxHeight: 40,
    lineHeight: '40px',
    color: theme.palette.text?.primary,
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
    color: theme.palette.text?.primary,
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

interface StixCoreRelationshipCreationFormInput {
  confidence: string;
  fromId: string;
  toId: string;
  relationship_type: string;
  start_time?: string;
  stop_time?: string;
  killChainPhases: FieldOption[];
  createdBy?: FieldOption;
  objectMarking: FieldOption[];
  externalReferences: FieldOption[];
}

interface StixCoreRelationshipCreationAddInput {
  confidence: number;
  fromId: string;
  toId: string;
  relationship_type: string;
  start_time: string | null;
  stop_time: string | null;
  killChainPhases: (string | null | undefined)[];
  createdBy?: string | null;
  objectMarking: (string | null | undefined)[];
  externalReferences: (string | null | undefined)[];
}

interface StixCoreRelationshipCreationProps {
  onClose: () => void;
  onReverseRelation: () => void;
  fromObjects: (GraphNode | GraphLink)[];
  toObjects: (GraphNode | GraphLink)[];
  handleResult: (rel: ObjectToParse) => void;
  confidence?: number | null;
  startTime: string;
  stopTime: string;
  defaultCreatedBy: string | { label: string; type: string; value: string };
  defaultMarkingDefinitions: FieldOption[];
  open: boolean;
}

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
}: StixCoreRelationshipCreationProps) => {
  const classes = useStyles();
  const { t_i18n, fsd } = useFormatter();
  const theme = useTheme<Theme>();

  const [step, setStep] = useState(0);
  const [existingRelations, setExistingRelations] = useState<NonNullable<StixCoreRelationshipCreationQuery$data['stixCoreRelationships']>['edges']>([]);
  const [displayProgress, setDisplayProgress] = useState(false);
  const [progress, setProgress] = useState(0);
  const prevProps = useRef({ open, fromObjects, toObjects });

  const [commitAddRelation] = useApiMutation<StixCoreRelationshipCreationMutation>(stixCoreRelationshipCreationMutation);

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
            const { stixCoreRelationships } = data as StixCoreRelationshipCreationQuery$data;
            if (stixCoreRelationships) {
              const newStep = stixCoreRelationships.edges
                && stixCoreRelationships.edges.length > 0
                ? 1
                : 2;
              setStep(newStep);
              setExistingRelations(stixCoreRelationships.edges ?? []);
            }
          });
      } else {
        setStep(2);
        setExistingRelations([]);
      }
    }
    prevProps.current = { open, fromObjects, toObjects };
  }, [open, fromObjects, toObjects]);

  const handleCommitAddRelation = (values: StixCoreRelationshipCreationAddInput) => new Promise((resolve, reject) => {
    commitAddRelation({
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

  const handleClose = () => {
    setExistingRelations([]);
    setStep(0);
    onClose();
  };

  const handleCloseProgressBar = () => {
    setDisplayProgress(false);
  };

  const onSubmit: FormikConfig<StixCoreRelationshipCreationFormInput>['onSubmit'] = async (values, { resetForm }) => {
    setDisplayProgress(true);
    handleClose();
    resetForm();
    let latestResponse;
    let current = 1;
    const total = fromObjects.length * toObjects.length;
    for (const fromObject of fromObjects) {
      for (const toObject of toObjects) {
        const finalValues = {
          ...values,
          confidence: parseInt(values.confidence, 10),
          fromId: fromObject.id,
          toId: toObject.id,
          start_time: formatDate(values.start_time),
          stop_time: formatDate(values.stop_time),
          killChainPhases: values.killChainPhases.map((k) => k.value),
          createdBy: values.createdBy?.value,
          objectMarking: values.objectMarking.map((k) => k.value),
          externalReferences: values.externalReferences.map((k) => k.value),
        };

        latestResponse = await handleCommitAddRelation(finalValues);
        handleResult(latestResponse as ObjectToParse);
        current += 1;
        setProgress(Math.round((current * 100) / total));
      }
    }
    setDisplayProgress(false);
    setProgress(0);
  };

  const handleSelectRelation = (relation: ObjectToParse) => {
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
            schema?.schemaRelationsTypesMapping ?? new Map(),
          ));
          return (
            <>
              <div className={classes.header}>
                <IconButton
                  aria-label="Close"
                  className={classes.closeButton}
                  onClick={handleClose}
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
                handleResetSelection={undefined}
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
          >
            <Close fontSize="small" color="primary" />
          </IconButton>
          <Typography variant="h6">{t_i18n('Select a relationship')}</Typography>
        </div>
        <div style={{ padding: '10px 20px 20px 20px' }}>
          {existingRelations.map((relation) => (
            <div
              key={relation.node.id}
              className={classes.relation}
              onClick={() => handleSelectRelation(relation.node as unknown as ObjectToParse)}
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
                      color: theme.palette.text?.primary,
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
                  color: theme.palette.text?.primary,
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
        variant="determinate"
      />
    </>
  );
};

export default StixCoreRelationshipCreation;
