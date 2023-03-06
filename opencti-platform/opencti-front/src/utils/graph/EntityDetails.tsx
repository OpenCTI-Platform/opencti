import React, { FunctionComponent, useState } from 'react';
import makeStyles from '@mui/styles/makeStyles';
import Tooltip from '@mui/material/Tooltip';
import IconButton from '@mui/material/IconButton';
import { Link } from 'react-router-dom';
import { ExpandLessOutlined, ExpandMoreOutlined, InfoOutlined } from '@mui/icons-material';
import Typography from '@mui/material/Typography';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemText from '@mui/material/ListItemText';
import ListItemIcon from '@mui/material/ListItemIcon';
import Button from '@mui/material/Button';
import Chip from '@mui/material/Chip';
import { useFormatter } from '../../components/i18n';
import { resolveLink } from '../Entity';
import ItemAuthor from '../../components/ItemAuthor';
import useQueryLoading from '../hooks/useQueryLoading';
import Loader, { LoaderVariant } from '../../components/Loader';
import { EntityDetailsQuery } from './__generated__/EntityDetailsQuery.graphql';
import ExpandableMarkdown from '../../components/ExpandableMarkdown';
import ItemMarkings from '../../components/ItemMarkings';
import { truncate } from '../String';
import type { SelectedEntity } from './EntitiesDetailsRightBar';
import ErrorNotFound from '../../components/ErrorNotFound';
import ItemIcon from '../../components/ItemIcon';
import { Theme } from '../../components/Theme';

const useStyles = makeStyles<Theme>((theme) => ({
  entity: {
    marginTop: '20px',
  },
  label: {
    marginTop: '20px',
  },
  nameLabel: {
    marginTop: '15px',
    marginBottom: -1,
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
  report: {
    display: 'flex',
    alignItems: 'flex-end',
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
      externalReferences  {
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
            reports {
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

interface EntityDetailsComponentProps {
  queryRef: PreloadedQuery<EntityDetailsQuery>;
}

const EntityDetailsComponent: FunctionComponent<
EntityDetailsComponentProps
> = ({ queryRef }) => {
  const classes = useStyles();
  const { t, fldt } = useFormatter();

  const entity = usePreloadedQuery<EntityDetailsQuery>(
    entityDetailsQuery,
    queryRef,
  );
  const { stixCoreObject } = entity;

  const [expanded, setExpanded] = useState(false);

  const externalReferencesEdges = stixCoreObject?.externalReferences?.edges;
  const reportsEdges = stixCoreObject?.reports?.edges;
  const expandable = externalReferencesEdges
    ? externalReferencesEdges.length > 3
    : false;

  const handleToggleExpand = () => {
    setExpanded(!expanded);
  };

  if (!stixCoreObject) {
    return <ErrorNotFound />;
  }
  return (
    <div className={classes.entity}>
      <Typography
        variant="h3"
        gutterBottom={false}
        className={classes.nameLabel}
      >
        {t('Name')}
      </Typography>
      {stixCoreObject.name ? truncate(stixCoreObject.name, 30) : '-'}
      <Tooltip title={t('View the item')}>
          <span>
            <IconButton
              color="primary"
              component={Link}
              to={`${resolveLink(stixCoreObject.entity_type)}/${
                stixCoreObject.id
              }`}
              size="small"
            >
                <InfoOutlined/>
            </IconButton>
          </span>
      </Tooltip>
      <Typography
        variant="h3"
        gutterBottom={true}
        className={classes.label}
      >
        {t('Type')}
      </Typography>
      {stixCoreObject.entity_type}
      <Typography variant="h3"
                  gutterBottom={true}
                  className={classes.label}
      >
        {t('Creation date')}
      </Typography>
      {fldt(stixCoreObject.created_at)}
      <Typography
        variant="h3"
        gutterBottom={true}
        className={classes.label}
      >
        {t('Description')}
      </Typography>
      {stixCoreObject.description ? (
        <ExpandableMarkdown
          source={stixCoreObject.description}
          limit={400}
        />
      ) : (
        '-'
      )
      }
      <Typography variant="h3"
                  gutterBottom={true}
                  className={classes.label}
      >
        {t('Marking')}
      </Typography>
      {(stixCoreObject.objectMarking?.edges && stixCoreObject.objectMarking?.edges.length > 0) ? (
        <ItemMarkings
          markingDefinitionsEdges={stixCoreObject.objectMarking.edges}
          limit={2}
        />) : (
        '-'
      )
      }
      <Typography
        variant="h3"
        gutterBottom={true}
        className={classes.label}
      >
        {t('Author')}
      </Typography>
      <ItemAuthor
        createdBy={stixCoreObject.createdBy}
      />
      <Typography
        variant="h3"
        gutterBottom={true}
        className={classes.label}
      >
        {t('External References')}
      </Typography>
      {(externalReferencesEdges && externalReferencesEdges.length > 0)
        ? (<List style={{ marginBottom: 0 }}>
          {externalReferencesEdges
            .slice(0, expanded ? 200 : 3)
            .map((externalReference) => {
              const externalReferenceId = externalReference.node.external_id
                ? `(${externalReference.node.external_id})`
                : '';
              let externalReferenceSecondary = '';
              if (externalReference.node.url && externalReference.node.url.length > 0) {
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
                      <ItemIcon type="External-Reference"/>
                    </ListItemIcon>
                    <ListItemText
                      primary={truncate(
                        `${externalReference.node.source_name} ${externalReferenceId}`,
                        70,
                      )}
                      secondary={truncate(externalReferenceSecondary, 70)}
                    />
                  </ListItem>
                </div>
              );
            })}
        </List>)
        : (
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
            <ExpandLessOutlined fontSize="small"/>
          ) : (
            <ExpandMoreOutlined fontSize="small"/>
          )}
        </Button>
      )}
      <div
        className={classes.report}
      >
        <Typography
          variant="h3"
          gutterBottom={true}
          className={classes.label}
        >
          {t('Reports')}
        </Typography>
        {(reportsEdges && reportsEdges.length > 0)
          ? (<Chip
            color="primary"
            variant="outlined"
            label={reportsEdges.length}
            style={{ marginLeft: 10 }}
          />) : (
            ''
          )
        }
      </div>
      {(reportsEdges && reportsEdges.length > 0)
        ? (<List style={{ marginBottom: 0 }}>
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
                    <ItemIcon type={report.entity_type}/>
                  </ListItemIcon>
                  <ListItemText
                    primary={
                      <Tooltip title={report.name}>
                        <div className={classes.itemText}>
                          {report.name}
                        </div>
                      </Tooltip>
                    }
                  />
                </ListItem>
              );
            }
            return ('');
          })
          }
        </List>)
        : (
          '-'
        )
      }
    </div>
  );
};

interface EntityDetailsProps {
  entity: SelectedEntity;
  queryRef: PreloadedQuery<EntityDetailsQuery>;
}

const EntityDetails: FunctionComponent<
Omit<EntityDetailsProps, 'queryRef'>
> = ({ entity }) => {
  const queryRef = useQueryLoading<EntityDetailsQuery>(entityDetailsQuery, {
    id: entity.id,
  });
  return queryRef ? (
    <React.Suspense fallback={<Loader variant={LoaderVariant.inElement}/>}>
      <EntityDetailsComponent queryRef={queryRef}/>
    </React.Suspense>
  ) : (
    <Loader variant={LoaderVariant.inElement}/>
  );
};

export default EntityDetails;
