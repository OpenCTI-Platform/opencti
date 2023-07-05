import React, { FunctionComponent, useState } from 'react';
import makeStyles from '@mui/styles/makeStyles';
import Tooltip from '@mui/material/Tooltip';
import { Link } from 'react-router-dom';
import { ExpandLessOutlined, ExpandMoreOutlined } from '@mui/icons-material';
import Typography from '@mui/material/Typography';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemText from '@mui/material/ListItemText';
import ListItemIcon from '@mui/material/ListItemIcon';
import Button from '@mui/material/Button';
import Chip from '@mui/material/Chip';
import { useFormatter } from '../../components/i18n';
import ItemAuthor from '../../components/ItemAuthor';
import useQueryLoading from '../hooks/useQueryLoading';
import Loader, { LoaderVariant } from '../../components/Loader';
import { EntityDetailsQuery } from './__generated__/EntityDetailsQuery.graphql';
import ExpandableMarkdown from '../../components/ExpandableMarkdown';
import ItemMarkings from '../../components/ItemMarkings';
import type { SelectedEntity } from './EntitiesDetailsRightBar';
import ErrorNotFound from '../../components/ErrorNotFound';
import ItemIcon from '../../components/ItemIcon';
import { Theme } from '../../components/Theme';
import { defaultValue } from '../Graph';
import { hexToRGB, itemColor } from '../Colors';
import { truncate } from '../String';
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
    paddingRight: 10,
  },
  chipInList: {
    fontSize: 12,
    height: 20,
    width: 120,
    textTransform: 'uppercase',
    borderRadius: '0',
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
      ... on StixDomainObject {
        created
      }
      ... on AttackPattern {
        name
        x_mitre_id
        description
      }
      ... on Campaign {
        name
        description
        first_seen
        last_seen
      }
      ... on CourseOfAction {
        name
        description
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
        description
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
        description
      }
      ... on Vulnerability {
        name
        description
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
        description
      }
      ... on Case {
        name
        description
      }
      ... on Task {
        name
        description
      }
      ... on Channel {
          name
          description
      }
      ... on Narrative {
        name
        description
      }
      ... on DataComponent {
        name
        description
      }
      ... on DataSource {
        name
        description
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
    <div>
      <Typography variant="h3" gutterBottom={true} className={classes.label}>
        {t('Value')}
      </Typography>
      <Tooltip title={defaultValue(stixCoreObject, true)}>
        <span>{truncate(defaultValue(stixCoreObject), 40)}</span>
      </Tooltip>
      <Typography variant="h3" gutterBottom={true} className={classes.label}>
        {t('Type')}
      </Typography>
      <Chip
        classes={{ root: classes.chipInList }}
        style={{
          backgroundColor: hexToRGB(
            itemColor(stixCoreObject.entity_type),
            0.08,
          ),
          color: itemColor(stixCoreObject.entity_type),
          border: `1px solid ${itemColor(stixCoreObject.entity_type)}`,
        }}
        label={t(`entity_${stixCoreObject.entity_type}`)}
      />
      <Typography variant="h3" gutterBottom={true} className={classes.label}>
        {t('Creation date')}
      </Typography>
      {fldt(stixCoreObject.created_at)}
      <Typography variant="h3" gutterBottom={true} className={classes.label}>
        {t('Description')}
      </Typography>
      {stixCoreObject.description && stixCoreObject.description.length > 0 ? (
        <ExpandableMarkdown source={stixCoreObject.description} limit={400} />
      ) : (
        '-'
      )}
      <Typography variant="h3" gutterBottom={true} className={classes.label}>
        {t('Marking')}
      </Typography>
      {stixCoreObject.objectMarking?.edges
      && stixCoreObject.objectMarking?.edges.length > 0 ? (
        <ItemMarkings
          markingDefinitionsEdges={stixCoreObject.objectMarking.edges}
          limit={2}
        />
        ) : (
          '-'
        )}
      <Typography variant="h3" gutterBottom={true} className={classes.label}>
        {t('Author')}
      </Typography>
      <ItemAuthor createdBy={stixCoreObject.createdBy} />
      <Typography variant="h3" gutterBottom={true} className={classes.label}>
        {t('Creators')}
      </Typography>
      <div>
        {(stixCoreObject.creators ?? []).map((c) => {
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
          (stixCoreObject.reports?.pageInfo.globalCount ?? 0) >= 10
            ? 10
            : stixCoreObject.reports?.pageInfo.globalCount
        } ${t('reports')} ${t('of')} ${
          stixCoreObject.reports?.pageInfo.globalCount
        }`}
      </Typography>
      {reportsEdges && reportsEdges.length > 0 ? (
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
      ) : (
        '-'
      )}
      <Typography variant="h3" gutterBottom={true} className={classes.label}>
        {t('External references')}
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
    <React.Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
      <EntityDetailsComponent queryRef={queryRef} />
    </React.Suspense>
  ) : (
    <Loader variant={LoaderVariant.inElement} />
  );
};

export default EntityDetails;
