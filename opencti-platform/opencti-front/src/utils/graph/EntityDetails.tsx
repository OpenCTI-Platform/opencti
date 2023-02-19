import React, { FunctionComponent } from 'react';
import makeStyles from '@mui/styles/makeStyles';
import { Theme } from '@mui/material/styles/createTheme';
import ListItemText from '@mui/material/ListItemText';
import Tooltip from '@mui/material/Tooltip';
import IconButton from '@mui/material/IconButton';
import { Link } from 'react-router-dom';
import { InfoOutlined } from '@mui/icons-material';
import Typography from '@mui/material/Typography';
import * as R from 'ramda';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { useFormatter } from '../../components/i18n';
import { resolveLink } from '../Entity';
import ItemAuthor from '../../components/ItemAuthor';
import useQueryLoading from '../hooks/useQueryLoading';
import Loader, { LoaderVariant } from '../../components/Loader';
import { EntityDetailsQuery } from './__generated__/EntityDetailsQuery.graphql';
import ExpandableMarkdown from '../../components/ExpandableMarkdown';
import ItemMarkings from '../../components/ItemMarkings';
import { truncate } from '../String';
import type { SelectedLink, SelectedNode } from './EntitiesDetailsRightBar';
import { EntityDetailsRelationshipQuery } from './__generated__/EntityDetailsRelationshipQuery.graphql';
import ItemConfidence from '../../components/ItemConfidence';

const useStyles = makeStyles < Theme >(() => ({
  entity: {
    marginTop: '20px',
  },
}));

const entityDetailsQuery = graphql`
    query EntityDetailsQuery($id: String!) {
        stixCoreObject(id: $id) {
            id
            entity_type
            parent_types
            created_at
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
            ... on StixDomainObject {
                created
            }
            ... on AttackPattern {
                name
                x_mitre_id
            }
            ... on Campaign {
                name
                first_seen
                last_seen
            }
            ... on CourseOfAction {
                name
            }
            ... on Note {
                attribute_abstract
                content
            }
            ... on ObservedData {
                name
            }
            ... on Opinion {
                opinion
            }
            ... on Report {
                name
                published
            }
            ... on Grouping {
                name
                description
            }
            ... on Individual {
                name
                description
            }
            ... on Organization {
                name
                description
            }
            ... on Sector {
                name
                description
            }
            ... on System {
                name
                description
            }
            ... on Indicator {
                name
                description
            }
            ... on Infrastructure {
                name
                description
            }
            ... on IntrusionSet {
                name
                first_seen
                last_seen
                description
            }
            ... on Position {
                name
                description
            }
            ... on City {
                name
                description
            }
            ... on AdministrativeArea {
                name
                description
            }
            ... on Country {
                name
                description
            }
            ... on Region {
                name
                description
            }
            ... on Malware {
                name
                first_seen
                last_seen
                description
            }
            ... on ThreatActor {
                name
                first_seen
                last_seen
                description
            }
            ... on Tool {
                name
            }
            ... on Vulnerability {
                name
            }
            ... on Incident {
                name
                first_seen
                last_seen
                description
            }
            ... on StixCyberObservable {
                observable_value
            }
            ... on StixFile {
                observableName: name
            }
            ... on Event {
                name
            }
            ... on Case {
                name
            }
            ... on Narrative {
                name
            }
            ... on DataComponent {
                name
            }
            ... on DataSource {
                name
            }
            ... on Language {
                name
            }
        }
    }
`;

const entityDetailsRelationshipQuery = graphql`
    query EntityDetailsRelationshipQuery($id: String!) {
        stixCoreRelationship(id: $id) {
            id
            entity_type
            description
            parent_types
            start_time
            stop_time
            created
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

interface EntityDetailsComponentProps {
  queryRef: PreloadedQuery<EntityDetailsQuery>
}
const EntityDetailsComponent: FunctionComponent<EntityDetailsComponentProps> = ({ queryRef }) => {
  const classes = useStyles();
  const { t } = useFormatter();

  const entity = usePreloadedQuery<EntityDetailsQuery>(entityDetailsQuery, queryRef);
  console.log(entity);
  const { stixCoreObject } = entity;

  return (
    <div className={classes.entity}>
      <Typography
        variant="h3"
        gutterBottom={false}
        style={{ marginTop: 15 }}
      >
        {t('Name')}
      </Typography>
      {truncate(stixCoreObject?.name, 30)}
      { stixCoreObject
        && <Tooltip title={t('View the item')}>
                  <span>
                    <IconButton
                      color="primary"
                      component={Link}
                      to={`${resolveLink(stixCoreObject.entity_type)}/${
                        stixCoreObject.id
                      }`}
                      size="large"
                    >
                        <InfoOutlined/>
                    </IconButton>
                  </span>
        </Tooltip> }
      <Typography
        variant="h3"
        gutterBottom={true}
        style={{ marginTop: 15 }}
      >
        {t('Type')}
      </Typography>
      { stixCoreObject?.entity_type}
      { stixCoreObject?.description
        && <div>
          <Typography
            variant="h3"
            gutterBottom={true}
            style={{ marginTop: 15 }}
          >
            {t('Description')}
          </Typography>
         <ExpandableMarkdown
          source={ stixCoreObject?.description}
          limit={400}
        />
        </div>
      }
      { (stixCoreObject?.objectMarking?.edges.length && stixCoreObject?.objectMarking?.edges.length > 0)
       && <div>
        <Typography variant="h3"
        gutterBottom={true}
        style={{ marginTop: 15 }}
        >
      {t('Marking')}
        </Typography>
         <ItemMarkings
        markingDefinitionsEdges={ stixCoreObject?.objectMarking.edges}
        limit={2}
        />
      </div>
      }
      { stixCoreObject?.createdBy
        && <div>
          <Typography
            variant="h3"
            gutterBottom={true}
            style={{ marginTop: 15 }}
          >
            {t('Author')}
          </Typography>
          <ItemAuthor
            createdBy={R.propOr(null, 'createdBy', stixCoreObject)}
          />
        </div>
      }
    </div>
  );
};

interface RelationshipDetailsComponentProps {
  queryRef: PreloadedQuery<EntityDetailsRelationshipQuery>
}
const RelationshipDetailsComponent: FunctionComponent<RelationshipDetailsComponentProps> = ({ queryRef }) => {
  const classes = useStyles();
  const { t, fldt } = useFormatter();

  const entity = usePreloadedQuery<EntityDetailsRelationshipQuery>(entityDetailsRelationshipQuery, queryRef);
  const { stixCoreRelationship } = entity;
  console.log(entity);

  return (
    <div className={classes.entity}>
      <Typography
        variant="h3"
        gutterBottom={false}
        style={{ marginTop: 15 }}
      >
        {t('Relation type')}
      </Typography>
      {stixCoreRelationship?.relationship_type}
      { stixCoreRelationship
        && <Tooltip title={t('View the item')}>
                  <span>
                    <IconButton
                      color="primary"
                      component={Link}
                      to={`${resolveLink(stixCoreRelationship.entity_type)}/${
                        stixCoreRelationship.id
                      }`}
                      size="large"
                    >
                        <InfoOutlined/>
                    </IconButton>
                  </span>
        </Tooltip> }
      { stixCoreRelationship?.description
        && <div>
          <Typography
            variant="h3"
            gutterBottom={true}
            style={{ marginTop: 15 }}
          >
            {t('Description')}
          </Typography>
          <ExpandableMarkdown
            source={ stixCoreRelationship?.description}
            limit={400}
          />
        </div>
      }
      { stixCoreRelationship?.objectMarking
        && <Typography variant="h3"
                      gutterBottom={true}
                      style={{ marginTop: 15 }}
          >
            {t('Marking')}
          </Typography>
            && <ItemMarkings
              markingDefinitionsEdges={ stixCoreRelationship?.objectMarking.edges}
              limit={2}
            />
      }
      { stixCoreRelationship?.createdBy
        && <div>
        <Typography
          variant="h3"
          gutterBottom={true}
          style={{ marginTop: 15 }}
        >
          {t('Author')}
        </Typography>
        <ItemAuthor
          createdBy={R.propOr(null, 'createdBy', stixCoreRelationship)}
        />
      </div>
      }
      {stixCoreRelationship?.confidence
        && <div>
          <Typography
            variant="h3"
            gutterBottom={true}
            style={{ marginTop: 20 }}
          >
            {t('Confidence level')}
          </Typography>
          <ItemConfidence confidence={stixCoreRelationship?.confidence} />
        </div>
      }
      <Typography
        variant="h3"
        gutterBottom={true}
        style={{ marginTop: 20 }}
      >
        {t('First seen')}
      </Typography>
      {fldt(stixCoreRelationship?.start_time)}
      <Typography
        variant="h3"
        gutterBottom={true}
        style={{ marginTop: 20 }}
      >
        {t('Last seen')}
      </Typography>
      {fldt(stixCoreRelationship?.stop_time)}
    </div>
  );
};

interface EntityDetailsProps {
  entity: SelectedNode | SelectedLink
  queryRef: PreloadedQuery<EntityDetailsQuery>
}

const EntityDetails: FunctionComponent<Omit<EntityDetailsProps, 'queryRef'>> = ({ entity }) => {
  if (entity.entity_type === 'uses') {
    const queryRef = useQueryLoading<EntityDetailsRelationshipQuery>(entityDetailsRelationshipQuery, { id: entity.id });
    return queryRef ? (
      <React.Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
        <RelationshipDetailsComponent queryRef={queryRef} />
      </React.Suspense>
    ) : (
      <Loader variant={LoaderVariant.inElement} />
    );
  }
  const queryRef = useQueryLoading<EntityDetailsQuery>(entityDetailsQuery, { id: entity.id });
  return queryRef ? (
    <React.Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
      <EntityDetailsComponent queryRef={queryRef} />
    </React.Suspense>
  ) : (
    <Loader variant={LoaderVariant.inElement} />
  );
};

export default EntityDetails;
