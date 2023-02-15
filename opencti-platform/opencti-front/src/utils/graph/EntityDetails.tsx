import React, { FunctionComponent, useState } from 'react';
import makeStyles from '@mui/styles/makeStyles';
import Drawer from '@mui/material/Drawer';
import { Theme } from '@mui/material/styles/createTheme';
import List from '@mui/material/List';
import ListSubheader from '@mui/material/ListSubheader';
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
import { EntityDetailsQuery, EntityDetailsQuery$data } from './__generated__/EntityDetailsQuery.graphql';

const useStyles = makeStyles < Theme >((theme) => ({

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
                first_observed
                last_observed
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
            }
            ... on Organization {
                name
            }
            ... on Sector {
                name
            }
            ... on System {
                name
            }
            ... on Indicator {
                name
                valid_from
            }
            ... on Infrastructure {
                name
            }
            ... on IntrusionSet {
                name
                first_seen
                last_seen
            }
            ... on Position {
                name
            }
            ... on City {
                name
            }
            ... on AdministrativeArea {
                name
            }
            ... on Country {
                name
            }
            ... on Region {
                name
            }
            ... on Malware {
                name
                first_seen
                last_seen
            }
            ... on ThreatActor {
                name
                first_seen
                last_seen
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

interface EntityDetailsProps {
  id: string
  queryRef: PreloadedQuery<EntityDetailsQuery>
}
const EntityDetailsComponent: FunctionComponent<EntityDetailsProps> = ({ id, queryRef }) => {
  // const classes = useStyles();
  const { t } = useFormatter();

  const entity = usePreloadedQuery<EntityDetailsQuery>(entityDetailsQuery, queryRef);
  /*  const viewLink = (node: EntityDetailsQuery$data) => {
    if (
      !node.stixCoreObject?.parent_types.includes(
        'stix-cyber-observable-relationship',
      )
      && node.stixCoreObject?.relationship_type
      && node.stixCoreObject?.fromType
      && node.stixCoreObject?.entity_type
    ) {
      return `${resolveLink(node.stixCoreObject?.fromType)}/${
        node.stixCoreObject?.fromId
      }/knowledge/relations/${node.stixCoreObject?.id}`;
    }
    return `${resolveLink(node.stixCoreObject?.entity_type)}/${
      node.stixCoreObject?.id
    }`;
  }; */

  return (
    <div>
      <Typography
        variant="h3"
        gutterBottom={false}
        style={{ marginTop: 10 }}
      >
        {entity.stixCoreObject?.id}
{/*        <Tooltip title={t('View the item')}>
                  <span>
                    <IconButton
                      color="primary"
                      component={Link}
                      to={viewLink(entity)}
                      disabled={!viewLink(entity)}
                      size="large"
                    >
                      <InfoOutlined />
                    </IconButton>
                  </span>
        </Tooltip> */}
      </Typography>
      <Typography
        variant="h3"
        gutterBottom={true}
        style={{ marginTop: 15 }}
      >
        {t('Type')}
      </Typography>
      {entity.stixCoreObject?.entity_type}
      <Typography
        variant="h3"
        gutterBottom={true}
        style={{ marginTop: 15 }}
      >
        {t('Description')}
      </Typography>
      {entity.stixCoreObject?.description}
      <Typography variant="h3"
                  gutterBottom={true}
                  style={{ marginTop: 15 }}
      >
        {t('Marking')}
      </Typography>
      {'Entity marking'}
      <Typography
        variant="h3"
        gutterBottom={true}
        style={{ marginTop: 15 }}
      >
        {t('Author')}
      </Typography>
      <ItemAuthor
        createdBy={R.propOr(null, 'createdBy', entity)}
      />
      <Typography
        variant="h3"
        gutterBottom={true}
        style={{ marginTop: 15 }}
      >
        {t('Id')}
      </Typography>
      <ListItemText primary={entity.stixCoreObject?.id} />
    </div>
  );
};

const EntityDetails: FunctionComponent<Omit<EntityDetailsProps, 'queryRef'>> = (
  props,
) => {
  const nodeId = '946cc606-2f09-49bf-97b5-2b57847ff07a';
  const queryRef = useQueryLoading<EntityDetailsQuery>(entityDetailsQuery, { id: nodeId });
  return queryRef ? (
    <React.Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
      <EntityDetailsComponent {...props} queryRef={queryRef} />
    </React.Suspense>
  ) : (
    <Loader variant={LoaderVariant.inElement} />
  );
};

export default EntityDetails;
