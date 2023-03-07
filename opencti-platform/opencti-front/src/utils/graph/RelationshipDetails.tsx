import React, { FunctionComponent, useState } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import Typography from '@mui/material/Typography';
import Tooltip from '@mui/material/Tooltip';
import { Link } from 'react-router-dom';
import {
  ExpandLessOutlined,
  ExpandMoreOutlined,
} from '@mui/icons-material';
import makeStyles from '@mui/styles/makeStyles';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import Button from '@mui/material/Button';
import Chip from '@mui/material/Chip';
import useQueryLoading from '../hooks/useQueryLoading';
import Loader, { LoaderVariant } from '../../components/Loader';
import { useFormatter } from '../../components/i18n';
import ExpandableMarkdown from '../../components/ExpandableMarkdown';
import ItemMarkings from '../../components/ItemMarkings';
import ItemAuthor from '../../components/ItemAuthor';
import ItemConfidence from '../../components/ItemConfidence';
import { RelationshipDetailsQuery } from './__generated__/RelationshipDetailsQuery.graphql';
import type { SelectedEntity } from './EntitiesDetailsRightBar';
import ErrorNotFound from '../../components/ErrorNotFound';
import RelationShipFromAndTo from './RelationShipFromAndTo';
import { Theme } from '../../components/Theme';
import ItemIcon from '../../components/ItemIcon';
import { hexToRGB, itemColor } from '../Colors';
import ItemCreator from '../../components/ItemCreator';

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
    paddingRight: 5,
  },
  chipInList: {
    fontSize: 12,
    height: 20,
    width: 120,
    textTransform: 'uppercase',
    borderRadius: '0',
  },
  external: {
    position: 'fixed',
    bottom: 5,
    right: 5,
    color: theme.palette.text?.secondary,
  },
}));

const relationshipDetailsQuery = graphql`
  query RelationshipDetailsQuery($id: String!) {
    stixCoreRelationship(id: $id) {
      id
      entity_type
      description
      parent_types
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
      created_at
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
  }
`;

interface RelationshipDetailsComponentProps {
  queryRef: PreloadedQuery<RelationshipDetailsQuery>;
}

const RelationshipDetailsComponent: FunctionComponent<
RelationshipDetailsComponentProps
> = ({ queryRef }) => {
  const classes = useStyles();
  const { t, fldt } = useFormatter();
  const entity = usePreloadedQuery<RelationshipDetailsQuery>(
    relationshipDetailsQuery,
    queryRef,
  );
  const { stixCoreRelationship } = entity;
  const [expanded, setExpanded] = useState(false);
  const externalReferencesEdges = stixCoreRelationship?.externalReferences?.edges;
  const reportsEdges = stixCoreRelationship?.reports?.edges;
  const expandable = externalReferencesEdges
    ? externalReferencesEdges.length > 3
    : false;
  const handleToggleExpand = () => {
    setExpanded(!expanded);
  };
  if (!stixCoreRelationship) {
    return <ErrorNotFound />;
  }
  return (
    <div>
      <Typography variant="h3" gutterBottom={true} className={classes.label}>
        {t('Relation type')}
      </Typography>
      <Chip
        classes={{ root: classes.chipInList }}
        style={{
          backgroundColor: hexToRGB(
            itemColor(stixCoreRelationship.relationship_type),
            0.08,
          ),
          color: itemColor(stixCoreRelationship.relationship_type),
          border: `1px solid ${itemColor(
            stixCoreRelationship.relationship_type,
          )}`,
        }}
        label={t(`relationship_${stixCoreRelationship.relationship_type}`)}
      />
      {!stixCoreRelationship.from.relationship_type
        && stixCoreRelationship.from.id && (
          <RelationShipFromAndTo
            id={stixCoreRelationship.from.id}
            direction={'From'}
          />
      )}
      {stixCoreRelationship.from.relationship_type
        && stixCoreRelationship.from.id && (
          <div>
            <Typography
              variant="h3"
              gutterBottom={true}
              className={classes.label}
            >
              {t('Source')}
            </Typography>
            {stixCoreRelationship.from.relationship_type}
          </div>
      )}
      {!stixCoreRelationship.to.relationship_type
        && stixCoreRelationship.to.id && (
          <RelationShipFromAndTo
            id={stixCoreRelationship.to.id}
            direction={'To'}
          />
      )}
      {stixCoreRelationship.to.relationship_type
        && stixCoreRelationship.to.id && (
          <div>
            <Typography
              variant="h3"
              gutterBottom={true}
              className={classes.label}
            >
              {t('Target')}
            </Typography>
            {stixCoreRelationship.to.relationship_type}
          </div>
      )}
      <Typography variant="h3" gutterBottom={true} className={classes.label}>
        {t('Creation date')}
      </Typography>
      {fldt(stixCoreRelationship.created_at)}
      <Typography variant="h3" gutterBottom={true} className={classes.label}>
        {t('First seen')}
      </Typography>
      {fldt(stixCoreRelationship.start_time)}
      <Typography variant="h3" gutterBottom={true} className={classes.label}>
        {t('Last seen')}
      </Typography>
      {fldt(stixCoreRelationship.stop_time)}
      <Typography variant="h3" gutterBottom={true} className={classes.label}>
        {t('Description')}
      </Typography>
      {stixCoreRelationship.description
      && stixCoreRelationship.description.length > 0 ? (
        <ExpandableMarkdown
          source={stixCoreRelationship.description}
          limit={400}
        />
        ) : (
          '-'
        )}
      <Typography variant="h3" gutterBottom={true} className={classes.label}>
        {t('Confidence level')}
      </Typography>
      {stixCoreRelationship.confidence ? (
        <ItemConfidence confidence={stixCoreRelationship.confidence} entityType="stix-core-relationship" />
      ) : (
        '-'
      )}
      <Typography variant="h3" gutterBottom={true} className={classes.label}>
        {t('Marking')}
      </Typography>
      {stixCoreRelationship.objectMarking
      && stixCoreRelationship.objectMarking.edges.length > 0 ? (
        <ItemMarkings
          markingDefinitionsEdges={stixCoreRelationship.objectMarking.edges}
          limit={2}
        />
        ) : (
          '-'
        )}
      <Typography variant="h3" gutterBottom={true} className={classes.label}>
        {t('Author')}
      </Typography>
      <ItemAuthor createdBy={stixCoreRelationship.createdBy} />
      <Typography variant="h3" gutterBottom={true} className={classes.label}>
        {t('Creators')}
      </Typography>
      <div>
        {(stixCoreRelationship.creators ?? []).map((c) => {
          return (
            <div
              key={`creator-${c.id}`}
              style={{ float: 'left', marginRight: '10px' }}
            >
              <ItemCreator creator={c} />
            </div>
          );
        })}
        <div style={{ clear: 'both' }} />
      </div>
      <Typography variant="h3" gutterBottom={true} className={classes.label}>
        {`${t('Last')} ${
          (stixCoreRelationship.reports?.pageInfo.globalCount ?? 0) >= 10
            ? 10
            : stixCoreRelationship.reports?.pageInfo.globalCount
        } ${t('reports')} ${t('of')} ${
          stixCoreRelationship.reports?.pageInfo.globalCount
        }`}
      </Typography>
      {reportsEdges && reportsEdges.length > 0 && (
        <List style={{ marginBottom: 0 }}>
          {reportsEdges.map((reportEdge) => {
            const report = reportEdge?.node;
            if (report) {
              return (
                <ListItem
                  key={report.id}
                  dense={true}
                  button={true}
                  classes={{ root: classes.item }}
                  divider={true}
                  component={Link}
                  to={`/dashboard/analysis/reports/${report.id}`}
                >
                  <ListItemIcon>
                    <ItemIcon type={report.entity_type} />
                  </ListItemIcon>
                  <ListItemText
                    primary={
                      <Tooltip title={report.name}>
                        <div className={classes.bodyItem}>{report.name}</div>
                      </Tooltip>
                    }
                    secondary={
                      <div className={classes.bodyItem}>
                        {report.createdBy?.name ?? '-'}
                      </div>
                    }
                  />
                </ListItem>
              );
            }
            return '';
          })}
        </List>
      )}
      <Typography variant="h3" gutterBottom={true} className={classes.label}>
        {t('External References')}
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
                externalReferenceSecondary = t('No description');
              }
              return (
                <div key={externalReference.node.id}>
                  <ListItem
                    component={Link}
                    to={`/dashboard/analysis/external_references/${externalReference.node.id}`}
                    dense={true}
                    divider={true}
                    button={true}
                  >
                    <ListItemIcon>
                      <ItemIcon type="External-Reference" />
                    </ListItemIcon>
                    <ListItemText
                      primary={
                        <div className={classes.bodyItem}>
                          {`${externalReference.node.source_name} ${externalReferenceId}`}
                        </div>
                      }
                      secondary={
                        <div className={classes.bodyItem}>
                          {externalReferenceSecondary}
                        </div>
                      }
                    />
                  </ListItem>
                </div>
              );
            })}
        </List>
      ) : (
        '-'
      )}
      {expandable && (
        <Button
          variant="contained"
          size="small"
          onClick={handleToggleExpand}
          className={classes.buttonExpand}
        >
          {expanded ? (
            <ExpandLessOutlined fontSize="small" />
          ) : (
            <ExpandMoreOutlined fontSize="small" />
          )}
        </Button>
      )}
    </div>
  );
};

interface RelationshipDetailsProps {
  relation: SelectedEntity;
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
