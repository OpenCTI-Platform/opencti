import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import { Link } from 'react-router-dom';
import withStyles from '@mui/styles/withStyles';
import IconButton from '@common/button/IconButton';
import List from '@mui/material/List';
import ListItemText from '@mui/material/ListItemText';
import ListItemIcon from '@mui/material/ListItemIcon';
import Collapse from '@mui/material/Collapse';
import { Launch } from 'mdi-material-ui';
import { ExpandLess, ExpandMore } from '@mui/icons-material';
import { createRefetchContainer, graphql } from 'react-relay';
import { ListItemButton } from '@mui/material';
import ListItem from '@mui/material/ListItem';
import { yearFormat } from '../../../../utils/Time';
import inject18n from '../../../../components/i18n';
import StixCoreRelationshipPopover from '../stix_core_relationships/StixCoreRelationshipPopover';
import ItemYears from '../../../../components/ItemYears';
import ItemIcon from '../../../../components/ItemIcon';
import { stixDomainObjectThreatKnowledgeStixRelationshipsQuery } from './StixDomainObjectThreatKnowledgeQuery';
import ItemMarkings from '../../../../components/ItemMarkings';
import MarkdownDisplay from '../../../../components/MarkdownDisplay';

const styles = (theme) => ({
  itemIcon: {
    color: theme.palette.primary.main,
  },
  nested: {
    paddingLeft: theme.spacing(4),
  },
});

class StixDomainObjectGlobalKillChainComponent extends Component {
  constructor(props) {
    super(props);
    this.state = { expandedLines: {} };
  }

  handleToggleLine(lineKey) {
    this.setState({
      expandedLines: R.assoc(
        lineKey,
        this.state.expandedLines[lineKey] !== undefined
          ? !this.state.expandedLines[lineKey]
          : false,
        this.state.expandedLines,
      ),
    });
  }

  render() {
    const { t, classes, data, entityLink, paginationOptions, stixDomainObjectId } = this.props;
    // Extract all kill chain phases
    const killChainPhases = R.pipe(

      R.map((n) => (n.node
        && n.node.killChainPhases
        && n.node.killChainPhases.length > 0
        ? n.node.killChainPhases[0]
        : n.node
          && n.node.to
          && n.node.to.killChainPhases
          && n.node.to.killChainPhases.length > 0
          ? n.node.to.killChainPhases[0]
          : { id: 'unknown', phase_name: t('Unknown'), x_opencti_order: 99 })),
      R.uniq,
      R.indexBy(R.prop('id')),
    )(data.stixRelationships.edges);
    const stixRelationships = R.pipe(
      R.map((n) => n.node),
      R.map((n) => R.assoc(
        'startTimeYear',
        yearFormat(n.start_time) === '1970'
          ? t('None')
          : yearFormat(n.start_time),
        n,
      )),
      R.map((n) => R.assoc(
        'stopTimeYear',
        yearFormat(n.stop_time) === '5138'
          ? t('None')
          : yearFormat(n.stop_time),
        n,
      )),
      R.map((n) => R.assoc(
        'years',
        n.startTimeYear === n.stopTimeYear
          ? n.startTimeYear
          : `${n.startTimeYear} - ${n.stopTimeYear}`,
        n,
      )),
      R.map((n) => R.assoc(
        'killChainPhase',

        n && n.killChainPhases && n.killChainPhases.length > 0
          ? n.killChainPhases[0]
          : n
            && n.to
            && n.to.killChainPhases
            && n.to.killChainPhases.length > 0
            ? n.to.killChainPhases[0]
            : { id: 'unknown', phase_name: t('Unknown'), x_opencti_order: 99 },
        n,
      )),
      R.sortWith([R.ascend(R.prop('years'))]),
      R.groupBy(R.path(['killChainPhase', 'id'])),
      R.mapObjIndexed((value, key) => R.assoc('stixDomainObjects', value, killChainPhases[key])),
      R.values,
      R.sortWith([R.ascend(R.prop('x_opencti_order'))]),
    )(data.stixRelationships.edges);
    return (
      <div style={{ marginBottom: 90 }}>
        <div id="container">
          <List id="test">
            {stixRelationships.map((stixRelationship) => (
              <div key={stixRelationship.id}>
                <ListItem
                  divider={true}
                  disablePadding
                  secondaryAction={(
                    <IconButton
                      onClick={this.handleToggleLine.bind(
                        this,
                        stixRelationship.id,
                      )}
                      aria-haspopup="true"
                    >
                      {this.state.expandedLines[stixRelationship.id]
                        === false ? (
                            <ExpandMore />
                          ) : (
                            <ExpandLess />
                          )}
                    </IconButton>
                  )}
                >
                  <ListItemButton
                    onClick={this.handleToggleLine.bind(
                      this,
                      stixRelationship.id,
                    )}
                  >
                    <ListItemIcon>
                      <Launch color="primary" role="img" />
                    </ListItemIcon>
                    <ListItemText primary={stixRelationship.phase_name} />
                  </ListItemButton>
                </ListItem>
                <Collapse
                  in={this.state.expandedLines[stixRelationship.id] !== false}
                >
                  <List>
                    {stixRelationship.stixDomainObjects.map(
                      (stixDomainObject) => {
                        const entityToDisplay = (stixDomainObject.to?.id === stixDomainObjectId) ? stixDomainObject.from : stixDomainObject.to;
                        const restricted = entityToDisplay === null;
                        const link = `${entityLink}/relations/${stixDomainObject.id}`;
                        return (
                          <ListItem
                            key={stixDomainObject.id}
                            divider={true}
                            dense={true}
                            disablePadding
                            secondaryAction={(
                              <StixCoreRelationshipPopover
                                stixCoreRelationshipId={stixDomainObject.id}
                                paginationOptions={paginationOptions}
                                onDelete={this.props.relay.refetch.bind(this)}
                              />
                            )}
                          >
                            <ListItemButton
                              classes={{ root: classes.nested }}
                              component={Link}
                              to={link}
                            >
                              <ListItemIcon className={classes.itemIcon}>
                                <ItemIcon
                                  type={
                                    !restricted
                                      ? entityToDisplay.entity_type
                                      : 'restricted'
                                  }
                                />
                              </ListItemIcon>
                              <ListItemText
                                primary={

                                  !restricted ? (
                                    entityToDisplay.entity_type
                                    === 'Attack-Pattern' ? (
                                          <span>
                                            <strong>
                                              {entityToDisplay.x_mitre_id}
                                            </strong>{' '}
                                            - {entityToDisplay.name}
                                          </span>
                                        ) : (
                                          <span>{entityToDisplay.name}</span>
                                        )
                                  ) : (
                                    t('Restricted')
                                  )
                                }
                                secondary={
                                  stixDomainObject.description
                                  && stixDomainObject.description.length > 0 ? (
                                        <MarkdownDisplay
                                          content={stixDomainObject.description}
                                          remarkGfmPlugin={true}
                                          commonmark={true}
                                        />
                                      ) : (
                                        t('No description of this usage')
                                      )
                                }
                              />
                              <ItemMarkings
                                variant="inList"
                                markingDefinitions={stixDomainObject.objectMarking ?? []}
                                limit={1}
                              />
                              <ItemYears
                                variant="inList"
                                years={stixDomainObject.years}
                              />
                            </ListItemButton>
                          </ListItem>
                        );
                      },
                    )}
                  </List>
                </Collapse>
              </div>
            ))}
          </List>
        </div>
      </div>
    );
  }
}

StixDomainObjectGlobalKillChainComponent.propTypes = {
  stixDomainObjectId: PropTypes.string,
  data: PropTypes.object,
  entityLink: PropTypes.string,
  paginationOptions: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

const StixDomainObjectGlobalKillChain = createRefetchContainer(
  StixDomainObjectGlobalKillChainComponent,
  {
    data: graphql`
      fragment StixDomainObjectGlobalKillChain_data on Query {
        stixRelationships(
          fromOrToId: $fromOrToId
          elementWithTargetTypes: $elementWithTargetTypes
          relationship_type: $relationship_type
          first: $first
          orderBy: $orderBy
          orderMode: $orderMode
          filters: $filters
        ) {
          edges {
            node {
              id
              entity_type
              ... on StixCoreRelationship {
                description
                created
                start_time
                stop_time
                killChainPhases {
                  id
                  phase_name
                  x_opencti_order
                }
                objectMarking {
                  id
                  definition_type
                  definition
                  x_opencti_order
                  x_opencti_color
                }
              }
              to {
                ... on BasicObject {
                  id
                  entity_type
                }
                ... on AttackPattern {
                  name
                  x_mitre_id
                  killChainPhases {
                    id
                    phase_name
                    x_opencti_order
                  }
                }
                ... on Campaign {
                  name
                }
                ... on CourseOfAction {
                  name
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
                }
                ... on Infrastructure {
                  name
                }
                ... on IntrusionSet {
                  name
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
                  killChainPhases {
                    id
                    phase_name
                    x_opencti_order
                  }
                }
                ... on ThreatActor {
                  name
                }
                ... on Tool {
                  name
                  killChainPhases {
                    id
                    phase_name
                    x_opencti_order
                  }
                }
                ... on Vulnerability {
                  name
                }
                ... on Incident {
                  name
                }
              }
              from {
                  ... on BasicObject {
                      id
                      entity_type
                  }
                  ... on AttackPattern {
                      name
                      x_mitre_id
                      killChainPhases {
                          id
                          phase_name
                          x_opencti_order
                      }
                  }
                  ... on Campaign {
                      name
                  }
                  ... on CourseOfAction {
                      name
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
                  }
                  ... on Infrastructure {
                      name
                  }
                  ... on IntrusionSet {
                      name
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
                      killChainPhases {
                          id
                          phase_name
                          x_opencti_order
                      }
                  }
                  ... on ThreatActor {
                      name
                  }
                  ... on Tool {
                      name
                      killChainPhases {
                          id
                          phase_name
                          x_opencti_order
                      }
                  }
                  ... on Vulnerability {
                      name
                  }
                  ... on Incident {
                      name
                  }
              }
            }
          }
        }
      }
    `,
  },
  stixDomainObjectThreatKnowledgeStixRelationshipsQuery,
);

export default R.compose(
  inject18n,
  withStyles(styles),
)(StixDomainObjectGlobalKillChain);
