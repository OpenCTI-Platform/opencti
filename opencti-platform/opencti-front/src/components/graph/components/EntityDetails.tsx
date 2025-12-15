import React, { FunctionComponent, useState } from 'react';
import makeStyles from '@mui/styles/makeStyles';
import Tooltip from '@mui/material/Tooltip';
import { Link } from 'react-router-dom';
import { ExpandLessOutlined, ExpandMoreOutlined } from '@mui/icons-material';
import Typography from '@mui/material/Typography';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import List from '@mui/material/List';
import ListItemText from '@mui/material/ListItemText';
import ListItemIcon from '@mui/material/ListItemIcon';
import IconButton from '@common/button/IconButton';
import { ListItemButton } from '@mui/material';
import { useFormatter } from '../../i18n';
import ItemAuthor from '../../ItemAuthor';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import Loader, { LoaderVariant } from '../../Loader';
import ExpandableMarkdown from '../../ExpandableMarkdown';
import ItemMarkings from '../../ItemMarkings';
import ErrorNotFound from '../../ErrorNotFound';
import ItemIcon from '../../ItemIcon';
import type { Theme } from '../../Theme';
import { getMainRepresentative } from '../../../utils/defaultRepresentatives';
import { truncate } from '../../../utils/String';
import ItemCreators from '../../ItemCreators';
import { EntityDetailsQuery } from './__generated__/EntityDetailsQuery.graphql';
import ItemConfidence from '../../ItemConfidence';
import FieldOrEmpty from '../../FieldOrEmpty';
import ItemEntityType from '../../ItemEntityType';
import { GraphNode } from '../graph.types';

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
      ... on StixDomainObject {
        created
        confidence
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
      ... on MalwareAnalysis {
        result_name
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
        x_opencti_description
      }
      ... on StixFile {
        observableName: name
        x_opencti_additional_names
        hashes {
          algorithm
          hash
        }
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
  const { t_i18n, fldt } = useFormatter();
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
  const entityDescription = stixCoreObject.description || stixCoreObject.x_opencti_description;
  return (
    <div>
      {stixCoreObject.entity_type !== 'StixFile' && (
        <>
          <Typography variant="h3" gutterBottom={true} className={classes.label}>
            {t_i18n('Value')}
          </Typography>
          <Tooltip title={getMainRepresentative(stixCoreObject)}>
            <span>{truncate(getMainRepresentative(stixCoreObject), 40)}</span>
          </Tooltip>
        </>
      )}
      {stixCoreObject.entity_type === 'StixFile' && (
        <>
          {stixCoreObject.hashes && stixCoreObject.hashes.map((hashObj, index) => (hashObj ? (
            <div key={`${hashObj.algorithm}-${index}`}>
              <Typography variant="h3" gutterBottom={true} className={classes.label}>
                {hashObj.algorithm ? String(hashObj.algorithm) : ''}
              </Typography>
              <Tooltip title={hashObj.hash ? String(hashObj.hash) : ''}>
                <span>{truncate(hashObj.hash, 40)}</span>
              </Tooltip>
            </div>
          ) : null))}

          {stixCoreObject.observableName && (
            <>
              <Typography variant="h3" gutterBottom={true} className={classes.label}>
                {t_i18n('Name')}
              </Typography>
              <span>{stixCoreObject.observableName}</span>
            </>
          )}

          {stixCoreObject.x_opencti_additional_names && (
            (() => {
              const filteredAdditionalNames = stixCoreObject.x_opencti_additional_names.filter(
                (additionalName) => additionalName !== stixCoreObject.observableName,
              );
              return filteredAdditionalNames.length > 0 ? (
                <>
                  <Typography variant="h3" gutterBottom={true} className={classes.label}>
                    {t_i18n('Additional Names')}
                  </Typography>
                  <span>{filteredAdditionalNames.join(', ')}</span>
                </>
              ) : null;
            })()
          )}
        </>
      )}
      <Typography variant="h3" gutterBottom={true} className={classes.label}>
        {t_i18n('Type')}
      </Typography>
      <ItemEntityType entityType={stixCoreObject.entity_type} inList={false} />
      <Typography variant="h3" gutterBottom={true} className={classes.label}>
        {t_i18n('Platform creation date')}
      </Typography>
      {fldt(stixCoreObject.created_at)}
      <Typography variant="h3" gutterBottom={true} className={classes.label}>
        {t_i18n('Description')}
      </Typography>
      {entityDescription && entityDescription.length > 0 ? (
        <ExpandableMarkdown source={entityDescription} limit={400} />
      ) : (
        '-'
      )}
      {!stixCoreObject.parent_types.includes('Stix-Cyber-Observable') && (
        <div>
          <Typography
            variant="h3"
            gutterBottom={true}
            className={classes.label}
          >
            {t_i18n('Confidence level')}
          </Typography>
          <FieldOrEmpty source={stixCoreObject.confidence}>
            {stixCoreObject.confidence && (
              <ItemConfidence
                confidence={stixCoreObject.confidence}
                entityType="stix-core-object"
              />
            )}
          </FieldOrEmpty>
        </div>
      )}
      <Typography variant="h3" gutterBottom={true} className={classes.label}>
        {t_i18n('Marking')}
      </Typography>
      {stixCoreObject.objectMarking
        && stixCoreObject.objectMarking.length > 0 ? (
            <ItemMarkings
              markingDefinitions={stixCoreObject.objectMarking}
              limit={2}
            />
          ) : (
            '-'
          )}
      <Typography variant="h3" gutterBottom={true} className={classes.label}>
        {t_i18n('Author')}
      </Typography>
      <ItemAuthor createdBy={stixCoreObject.createdBy} />
      <Typography variant="h3" gutterBottom={true} className={classes.label}>
        {t_i18n('Creators')}
      </Typography>
      <ItemCreators creators={stixCoreObject.creators ?? []} />
      <Typography variant="h3" gutterBottom={true} className={classes.label}>
        {`${t_i18n('Last')} ${
          (stixCoreObject.reports?.pageInfo.globalCount ?? 0) >= 10
            ? 10
            : stixCoreObject.reports?.pageInfo.globalCount
        } ${t_i18n('reports')} ${t_i18n('of')} ${stixCoreObject.reports?.pageInfo
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
        {t_i18n('External references')}
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

interface EntityDetailsProps {
  entity: GraphNode;
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
