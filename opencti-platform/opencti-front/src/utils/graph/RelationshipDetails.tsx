import React, { FunctionComponent } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import Typography from '@mui/material/Typography';
import Tooltip from '@mui/material/Tooltip';
import IconButton from '@mui/material/IconButton';
import { Link } from 'react-router-dom';
import { InfoOutlined } from '@mui/icons-material';
import makeStyles from '@mui/styles/makeStyles';
import { Theme } from '@mui/material/styles/createTheme';
import useQueryLoading from '../hooks/useQueryLoading';
import Loader, { LoaderVariant } from '../../components/Loader';
import { useFormatter } from '../../components/i18n';
import { resolveLink } from '../Entity';
import ExpandableMarkdown from '../../components/ExpandableMarkdown';
import ItemMarkings from '../../components/ItemMarkings';
import ItemAuthor from '../../components/ItemAuthor';
import ItemConfidence from '../../components/ItemConfidence';
import {
  RelationshipDetailsQuery,
} from './__generated__/RelationshipDetailsQuery.graphql';
import type { SelectedEntity } from './EntitiesDetailsRightBar';
import ErrorNotFound from '../../components/ErrorNotFound';

const useStyles = makeStyles < Theme >(() => ({
  relation: {
    marginTop: '20px',
  },
  label: {
    marginTop: '20px',
  },
  relationTypeLabel: {
    marginTop: '15px',
    marginBottom: -1,
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
interface RelationshipDetailsComponentProps {
  queryRef: PreloadedQuery<RelationshipDetailsQuery>
}
const RelationshipDetailsComponent: FunctionComponent<RelationshipDetailsComponentProps> = ({ queryRef }) => {
  const classes = useStyles();
  const { t, fldt } = useFormatter();

  const entity = usePreloadedQuery<RelationshipDetailsQuery>(relationshipDetailsQuery, queryRef);
  const { stixCoreRelationship } = entity;

  if (!stixCoreRelationship) {
    return (<ErrorNotFound/>);
  }
  return (
    <div className={classes.relation}>
      <Typography
        variant="h3"
        gutterBottom={false}
        className={classes.relationTypeLabel}
      >
        {t('Relation type')}
      </Typography>
      {stixCoreRelationship.relationship_type}
      { stixCoreRelationship.from?.entity_type
        && <Tooltip title={t('View the item')}>
          <span>
            <IconButton
              color="primary"
              component={Link}
              to={`${resolveLink(stixCoreRelationship.from.entity_type)}/${
                stixCoreRelationship.from.id
              }/knowledge/relations/${stixCoreRelationship.id}`}
              size="small"
            >
                <InfoOutlined/>
            </IconButton>
          </span>
        </Tooltip> }
      { stixCoreRelationship.description
        && <div>
          <Typography
            variant="h3"
            gutterBottom={true}
            className={classes.label}
          >
            {t('Description')}
          </Typography>
          <ExpandableMarkdown
            source={ stixCoreRelationship.description}
            limit={400}
          />
        </div>
      }
      { (stixCoreRelationship.objectMarking && stixCoreRelationship.objectMarking?.edges.length > 0)
        && <div>
          <Typography variant="h3"
                      gutterBottom={true}
                      className={classes.label}
          >
            {t('Marking')}
          </Typography>
         <ItemMarkings
          markingDefinitionsEdges={ stixCoreRelationship.objectMarking.edges}
          limit={2}
        />
        </div>
      }
      { stixCoreRelationship.createdBy
        && <div>
          <Typography
            variant="h3"
            gutterBottom={true}
            className={classes.label}
          >
            {t('Author')}
          </Typography>
          <ItemAuthor
            createdBy={stixCoreRelationship.createdBy}
          />
        </div>
      }
      {stixCoreRelationship.confidence
        && <div>
          <Typography
            variant="h3"
            gutterBottom={true}
            className={classes.label}
          >
            {t('Confidence level')}
          </Typography>
          <ItemConfidence confidence={stixCoreRelationship.confidence} />
        </div>
      }
      <Typography
        variant="h3"
        gutterBottom={true}
        className={classes.label}
      >
        {t('First seen')}
      </Typography>
      {fldt(stixCoreRelationship.start_time)}
      <Typography
        variant="h3"
        gutterBottom={true}
        className={classes.label}
      >
        {t('Last seen')}
      </Typography>
      {fldt(stixCoreRelationship.stop_time)}
    </div>
  );
};

interface RelationshipDetailsProps {
  relation: SelectedEntity
  queryRef: PreloadedQuery<RelationshipDetailsQuery>
}
const RelationshipDetails: FunctionComponent<Omit<RelationshipDetailsProps, 'queryRef'>> = ({ relation }) => {
  const queryRef = useQueryLoading<RelationshipDetailsQuery>(relationshipDetailsQuery, { id: relation.id });
  return queryRef ? (
    <React.Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
      <RelationshipDetailsComponent queryRef={queryRef} />
    </React.Suspense>
  ) : (
    <Loader variant={LoaderVariant.inElement} />
  );
};

export default RelationshipDetails;
