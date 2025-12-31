import React, { FunctionComponent, useState } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import Typography from '@mui/material/Typography';
import Tooltip from '@mui/material/Tooltip';
import { Link } from 'react-router-dom';
import { ExpandLessOutlined, ExpandMoreOutlined } from '@mui/icons-material';
import makeStyles from '@mui/styles/makeStyles';
import List from '@mui/material/List';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import IconButton from '@common/button/IconButton';
import { ListItemButton } from '@mui/material';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import Loader, { LoaderVariant } from '../../Loader';
import { useFormatter } from '../../i18n';
import ExpandableMarkdown from '../../ExpandableMarkdown';
import ItemMarkings from '../../ItemMarkings';
import ItemAuthor from '../../ItemAuthor';
import ItemConfidence from '../../ItemConfidence';
import ErrorNotFound from '../../ErrorNotFound';
import RelationShipFromAndTo from './RelationShipFromAndTo';
import type { Theme } from '../../Theme';
import ItemIcon from '../../ItemIcon';
import ItemCreators from '../../ItemCreators';
import { RelationshipDetailsQuery } from './__generated__/RelationshipDetailsQuery.graphql';
import ItemEntityType from '../../ItemEntityType';
import { GraphLink } from '../graph.types';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles<Theme>((theme) => ({
  label: {
    marginTop: '20px',
  },
  buttonExpand: {
    position: 'relative',
    left: 0,
    bottom: 0,
    width: '100%',
    height: 25,
    color: theme.palette.primary.main,
    backgroundColor:
      theme.palette.mode === 'dark'
        ? 'rgba(255, 255, 255, .1)'
        : 'rgba(0, 0, 0, .1)',
    borderTopLeftRadius: 0,
    borderTopRightRadius: 0,
    '&:hover': {
      backgroundColor:
        theme.palette.mode === 'dark'
          ? 'rgba(255, 255, 255, .2)'
          : 'rgba(0, 0, 0, .2)',
    },
  },
  bodyItem: {
    width: '100%',
    height: 20,
    fontSize: 13,
    float: 'left',
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    paddingRight: 10,
  },
}));

const relationshipDetailsQuery = graphql`
  query RelationshipDetailsQuery($id: String!) {
    stixRelationship(id: $id) {
      id
      entity_type
      parent_types
      ... on StixCoreRelationship {
        description
        start_time
        stop_time
        created
        created_at
        confidence
        relationship_type
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
        createdBy {
          ... on Identity {
            id
            name
            entity_type
          }
        }
        creators {
          id
          name
        }
        objectMarking {
          id
          definition_type
          definition
          x_opencti_order
          x_opencti_color
        }
        externalReferences {
          edges {
            node {
              id
              source_name
              url
              external_id
              description
            }
          }
        }
        reports(first: 10) {
          edges {
            node {
              id
              entity_type
              name
              description
              published
              report_types
              createdBy {
                ... on Identity {
                  id
                  name
                  entity_type
                }
              }
            }
          }
          pageInfo {
            globalCount
          }
        }
      }
      ... on StixRefRelationship {
        start_time
        stop_time
        created_at
        confidence
        relationship_type
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
        creators {
          id
          name
        }
        objectMarking {
          id
          definition_type
          definition
          x_opencti_order
          x_opencti_color
        }
        reports(first: 10) {
          edges {
            node {
              id
              entity_type
              name
              description
              published
              report_types
              createdBy {
                ... on Identity {
                  id
                  name
                  entity_type
                }
              }
            }
          }
          pageInfo {
            globalCount
          }
        }
      }
      ... on StixSightingRelationship {
        description
        created
        created_at
        updated_at
        confidence
        relationship_type
        first_seen
        last_seen
        from {
          ... on StixCoreObject {
            id
            parent_types
            entity_type
          }
          ... on StixCoreRelationship {
            id
            parent_types
            entity_type
            relationship_type
          }
        }
        to {
          ... on StixCoreObject {
            id
            parent_types
            entity_type
          }
          ... on StixCoreRelationship {
            id
            parent_types
            entity_type
            relationship_type
          }
        }
        createdBy {
          ... on Identity {
            id
            name
            entity_type
          }
        }
        creators {
          id
          name
        }
        objectMarking {
          id
          definition_type
          definition
          x_opencti_order
          x_opencti_color
        }
        reports(first: 10) {
          edges {
            node {
              id
              entity_type
              name
              description
              published
              report_types
              createdBy {
                ... on Identity {
                  id
                  name
                  entity_type
                }
              }
            }
          }
          pageInfo {
            globalCount
          }
        }
      }
    }
  }
`;

interface RelationshipDetailsComponentProps {
  queryRef: PreloadedQuery<RelationshipDetailsQuery>;
}

const RelationshipDetailsComponent: FunctionComponent<
  RelationshipDetailsComponentProps
> = ({ queryRef }) => {
  const classes = useStyles();
  const { t_i18n, fldt } = useFormatter();
  const entity = usePreloadedQuery<RelationshipDetailsQuery>(
    relationshipDetailsQuery,
    queryRef,
  );
  const { stixRelationship } = entity;
  const [expanded, setExpanded] = useState(false);
  const externalReferencesEdges = stixRelationship?.externalReferences?.edges;
  const reportsEdges = stixRelationship?.reports?.edges;
  const expandable = externalReferencesEdges
    ? externalReferencesEdges.length > 3
    : false;
  const handleToggleExpand = () => {
    setExpanded(!expanded);
  };
  if (!stixRelationship) {
    return <ErrorNotFound />;
  }

  const computeNotGenericDetails = () => {
    if (stixRelationship.parent_types.includes('stix-ref-relationship')) {
      return (
        <>
          <Typography
            variant="h3"
            gutterBottom={true}
            className={classes.label}
          >
            {t_i18n('Creators')}
          </Typography>
          <ItemCreators creators={stixRelationship.creators ?? []} />
        </>
      );
    }
    return (
      <>
        <Typography variant="h3" gutterBottom={true} className={classes.label}>
          {stixRelationship.entity_type !== 'stix-sighting-relationship'
            ? t_i18n('Start time')
            : t_i18n('First seen')}
        </Typography>
        {stixRelationship.entity_type !== 'stix-sighting-relationship'
          ? fldt(stixRelationship.start_time)
          : fldt(stixRelationship.first_seen)}
        <Typography variant="h3" gutterBottom={true} className={classes.label}>
          {stixRelationship.entity_type !== 'stix-sighting-relationship'
            ? t_i18n('Stop time')
            : t_i18n('Last seen')}
        </Typography>
        {stixRelationship.entity_type !== 'stix-sighting-relationship'
          ? fldt(stixRelationship.stop_time)
          : fldt(stixRelationship.last_seen)}
        <Typography variant="h3" gutterBottom={true} className={classes.label}>
          {t_i18n('Description')}
        </Typography>
        {stixRelationship.description
          && stixRelationship.description.length > 0 ? (
              <ExpandableMarkdown
                source={stixRelationship.description}
                limit={400}
              />
            ) : (
              '-'
            )}
        <Typography variant="h3" gutterBottom={true} className={classes.label}>
          {t_i18n('Confidence level')}
        </Typography>
        {stixRelationship.confidence ? (
          <ItemConfidence
            confidence={stixRelationship.confidence}
            entityType="stix-core-relationship"
          />
        ) : (
          '-'
        )}
        <Typography variant="h3" gutterBottom={true} className={classes.label}>
          {t_i18n('Marking')}
        </Typography>
        {stixRelationship.objectMarking && stixRelationship.objectMarking.length > 0 ? (
          <ItemMarkings
            markingDefinitions={stixRelationship.objectMarking}
            limit={2}
          />
        ) : ('-')}
        <Typography variant="h3" gutterBottom={true} className={classes.label}>
          {t_i18n('Author')}
        </Typography>
        {stixRelationship.createdBy ? (
          <ItemAuthor createdBy={stixRelationship.createdBy} />
        ) : (
          '-'
        )}
        <Typography variant="h3" gutterBottom={true} className={classes.label}>
          {t_i18n('Creators')}
        </Typography>
        <ItemCreators creators={stixRelationship.creators ?? []} />
        <Typography variant="h3" gutterBottom={true} className={classes.label}>
          {`${t_i18n('Last')} ${
            (stixRelationship.reports?.pageInfo.globalCount ?? 0) >= 10
              ? 10
              : stixRelationship.reports?.pageInfo.globalCount
          } ${t_i18n('reports')} ${t_i18n('of')} ${stixRelationship.reports?.pageInfo
            .globalCount}`}
        </Typography>
        {reportsEdges && reportsEdges.length > 0 ? (
          <List style={{ marginBottom: 0 }}>
            {reportsEdges.map((reportEdge) => {
              const report = reportEdge?.node;
              if (report) {
                return (
                  <ListItemButton
                    key={report.id}
                    dense={true}
                    classes={{ root: classes.item }}
                    divider={true}
                    component={Link}
                    to={`/dashboard/analyses/reports/${report.id}`}
                  >
                    <ListItemIcon>
                      <ItemIcon type={report.entity_type} />
                    </ListItemIcon>
                    <ListItemText
                      primary={(
                        <Tooltip title={report.name}>
                          <div className={classes.bodyItem}>{report.name}</div>
                        </Tooltip>
                      )}
                      secondary={(
                        <div className={classes.bodyItem}>
                          {report.createdBy?.name ?? '-'}
                        </div>
                      )}
                    />
                  </ListItemButton>
                );
              }
              return '';
            })}
          </List>
        ) : (
          '-'
        )}
        <Typography variant="h3" gutterBottom={true} className={classes.label}>
          {t_i18n('External References')}
        </Typography>
        {externalReferencesEdges && externalReferencesEdges.length > 0 ? (
          <List style={{ marginBottom: 0 }}>
            {externalReferencesEdges
              .slice(0, expanded ? 200 : 3)
              .map((externalReference) => {
                const externalReferenceId = externalReference.node.external_id
                  ? `(${externalReference.node.external_id})`
                  : '';
                let externalReferenceSecondary = '';
                if (
                  externalReference.node.url
                  && externalReference.node.url.length > 0
                ) {
                  externalReferenceSecondary = externalReference.node.url;
                } else if (
                  externalReference.node.description
                  && externalReference.node.description.length > 0
                ) {
                  externalReferenceSecondary = externalReference.node.description;
                } else {
                  externalReferenceSecondary = t_i18n('No description');
                }
                return (
                  <React.Fragment key={externalReference.node.id}>
                    <ListItemButton
                      component={Link}
                      to={`/dashboard/analyses/external_references/${externalReference.node.id}`}
                      dense={true}
                      divider={true}
                    >
                      <ListItemIcon>
                        <ItemIcon type="External-Reference" />
                      </ListItemIcon>
                      <ListItemText
                        primary={(
                          <div className={classes.bodyItem}>
                            {`${externalReference.node.source_name} ${externalReferenceId}`}
                          </div>
                        )}
                        secondary={(
                          <div className={classes.bodyItem}>
                            {externalReferenceSecondary}
                          </div>
                        )}
                      />
                    </ListItemButton>
                  </React.Fragment>
                );
              })}
          </List>
        ) : (
          '-'
        )}
      </>
    );
  };

  return (
    <div>
      <Typography variant="h3" gutterBottom={true} className={classes.label}>
        {t_i18n('Relation type')}
      </Typography>
      <ItemEntityType
        entityType={stixRelationship.relationship_type ?? 'unknown'}
        inList={false}
      />
      {!stixRelationship.from?.relationship_type
        && stixRelationship.from?.id && (
        <RelationShipFromAndTo
          id={stixRelationship.from?.id}
          direction="From"
        />
      )}
      {stixRelationship.from?.relationship_type
        && stixRelationship.from?.id && (
        <div>
          <Typography
            variant="h3"
            gutterBottom={true}
            className={classes.label}
          >
            {t_i18n('Source')}
          </Typography>
          {stixRelationship.from?.relationship_type}
        </div>
      )}
      {!stixRelationship.to?.relationship_type && stixRelationship.to?.id && (
        <RelationShipFromAndTo id={stixRelationship.to?.id} direction="To" />
      )}
      {stixRelationship.to?.relationship_type && stixRelationship.to?.id && (
        <div>
          <Typography
            variant="h3"
            gutterBottom={true}
            className={classes.label}
          >
            {t_i18n('Target')}
          </Typography>
          {stixRelationship.to?.relationship_type}
        </div>
      )}
      <Typography variant="h3" gutterBottom={true} className={classes.label}>
        {t_i18n('Platform creation date')}
      </Typography>
      {fldt(stixRelationship.created_at)}
      {computeNotGenericDetails()}
      {expandable && (
        <IconButton
          size="small"
          onClick={handleToggleExpand}
          className={classes.buttonExpand}
        >
          {expanded ? (
            <ExpandLessOutlined />
          ) : (
            <ExpandMoreOutlined />
          )}
        </IconButton>
      )}
    </div>
  );
};

interface RelationshipDetailsProps {
  relation: GraphLink;
  queryRef: PreloadedQuery<RelationshipDetailsQuery>;
}

const RelationshipDetails: FunctionComponent<
  Omit<RelationshipDetailsProps, 'queryRef'>
> = ({ relation }) => {
  const queryRef = useQueryLoading<RelationshipDetailsQuery>(
    relationshipDetailsQuery,
    { id: relation.id },
  );
  return queryRef ? (
    <React.Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
      <RelationshipDetailsComponent queryRef={queryRef} />
    </React.Suspense>
  ) : (
    <Loader variant={LoaderVariant.inElement} />
  );
};

export default RelationshipDetails;
