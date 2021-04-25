import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Link } from 'react-router-dom';
import Markdown from 'react-markdown';
import {
  compose,
  pipe,
  map,
  assoc,
  groupBy,
  path,
  mapObjIndexed,
  uniq,
  indexBy,
  prop,
  values,
  sortWith,
  ascend,
  take,
  pathOr,
} from 'ramda';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import IconButton from '@material-ui/core/IconButton';
import List from '@material-ui/core/List';
import ListItem from '@material-ui/core/ListItem';
import ListItemText from '@material-ui/core/ListItemText';
import ListItemIcon from '@material-ui/core/ListItemIcon';
import ListItemSecondaryAction from '@material-ui/core/ListItemSecondaryAction';
import Collapse from '@material-ui/core/Collapse';
import { Launch } from 'mdi-material-ui';
import { ExpandLess, ExpandMore } from '@material-ui/icons';
import { createRefetchContainer } from 'react-relay';
import { yearFormat } from '../../../../utils/Time';
import inject18n from '../../../../components/i18n';
import StixCoreRelationshipPopover from '../stix_core_relationships/StixCoreRelationshipPopover';
import ItemYears from '../../../../components/ItemYears';
import ItemMarking from '../../../../components/ItemMarking';
import ItemIcon from '../../../../components/ItemIcon';
import { stixDomainObjectThreatKnowledgeStixCoreRelationshipsQuery } from './StixDomainObjectThreatKnowledgeQuery';

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
      expandedLines: assoc(
        lineKey,
        this.state.expandedLines[lineKey] !== undefined
          ? !this.state.expandedLines[lineKey]
          : false,
        this.state.expandedLines,
      ),
    });
  }

  render() {
    const {
      t, classes, data, entityLink, paginationOptions,
    } = this.props;
    // Extract all kill chain phases
    const killChainPhases = pipe(
      // eslint-disable-next-line no-nested-ternary
      map((n) => (n.node.killChainPhases && n.node.killChainPhases.edges.length > 0
        ? n.node.killChainPhases.edges[0].node
        : n.node.to.killChainPhases
            && n.node.to.killChainPhases.edges.length > 0
          ? n.node.to.killChainPhases.edges[0].node
          : { id: 'unknown', phase_name: t('Unknown'), x_opencti_order: 99 })),
      uniq,
      indexBy(prop('id')),
    )(data.stixCoreRelationships.edges);
    const stixCoreRelationships = pipe(
      map((n) => n.node),
      map((n) => assoc(
        'startTimeYear',
        yearFormat(n.start_time) === '1970'
          ? t('None')
          : yearFormat(n.start_time),
        n,
      )),
      map((n) => assoc(
        'stopTimeYear',
        yearFormat(n.stop_time) === '5138'
          ? t('None')
          : yearFormat(n.stop_time),
        n,
      )),
      map((n) => assoc(
        'years',
        n.startTimeYear === n.stopTimeYear
          ? n.startTimeYear
          : `${n.startTimeYear} - ${n.stopTimeYear}`,
        n,
      )),
      map((n) => assoc(
        'killChainPhase',
        // eslint-disable-next-line no-nested-ternary
        n.killChainPhases && n.killChainPhases.edges.length > 0
          ? n.killChainPhases.edges[0].node
          : n.to.killChainPhases && n.to.killChainPhases.edges.length > 0
            ? n.to.killChainPhases.edges[0].node
            : { id: 'unknown', phase_name: t('Unknown'), x_opencti_order: 99 },
        n,
      )),
      sortWith([ascend(prop('years'))]),
      groupBy(path(['killChainPhase', 'id'])),
      mapObjIndexed((value, key) => assoc('stixDomainObjects', value, killChainPhases[key])),
      values,
      sortWith([ascend(prop('x_opencti_order'))]),
    )(data.stixCoreRelationships.edges);
    return (
      <div style={{ marginBottom: 90 }}>
        <div id="container">
          <List id="test">
            {stixCoreRelationships.map((stixCoreRelationship) => (
              <div key={stixCoreRelationship.id}>
                <ListItem
                  button={true}
                  divider={true}
                  onClick={this.handleToggleLine.bind(
                    this,
                    stixCoreRelationship.id,
                  )}
                >
                  <ListItemIcon>
                    <Launch color="primary" role="img" />
                  </ListItemIcon>
                  <ListItemText primary={stixCoreRelationship.phase_name} />
                  <ListItemSecondaryAction>
                    <IconButton
                      onClick={this.handleToggleLine.bind(
                        this,
                        stixCoreRelationship.id,
                      )}
                      aria-haspopup="true"
                    >
                      {this.state.expandedLines[stixCoreRelationship.id]
                      === false ? (
                        <ExpandMore />
                        ) : (
                        <ExpandLess />
                        )}
                    </IconButton>
                  </ListItemSecondaryAction>
                </ListItem>
                <Collapse
                  in={
                    this.state.expandedLines[stixCoreRelationship.id] !== false
                  }
                >
                  <List>
                    {stixCoreRelationship.stixDomainObjects.map(
                      (stixDomainObject) => {
                        const link = `${entityLink}/relations/${stixDomainObject.id}`;
                        return (
                          <ListItem
                            key={stixDomainObject.id}
                            classes={{ root: classes.nested }}
                            divider={true}
                            button={true}
                            dense={true}
                            component={Link}
                            to={link}
                          >
                            <ListItemIcon className={classes.itemIcon}>
                              <ItemIcon
                                type={stixDomainObject.to.entity_type}
                              />
                            </ListItemIcon>
                            <ListItemText
                              primary={
                                stixDomainObject.to.entity_type
                                === 'Attack-Pattern' ? (
                                  <span>
                                    <strong>
                                      {stixDomainObject.to.x_mitre_id}
                                    </strong>{' '}
                                    - {stixDomainObject.to.name}
                                  </span>
                                  ) : (
                                  <span>{stixDomainObject.to.name}</span>
                                  )
                              }
                              secondary={
                                stixDomainObject.description
                                && stixDomainObject.description.length > 0 ? (
                                  <Markdown
                                    className="markdown"
                                    source={stixDomainObject.description}
                                  />
                                  ) : (
                                    t('No description of this usage')
                                  )
                              }
                            />
                            {take(
                              1,
                              pathOr(
                                [],
                                ['markingDefinitions', 'edges'],
                                stixDomainObject,
                              ),
                            ).map((markingDefinition) => (
                              <ItemMarking
                                key={markingDefinition.node.id}
                                variant="inList"
                                label={markingDefinition.node.definition}
                                color={markingDefinition.node.x_opencti_color}
                              />
                            ))}
                            <ItemYears
                              variant="inList"
                              years={stixDomainObject.years}
                            />
                            <ListItemSecondaryAction>
                              <StixCoreRelationshipPopover
                                stixCoreRelationshipId={stixDomainObject.id}
                                paginationOptions={paginationOptions}
                                onDelete={this.props.relay.refetch.bind(this)}
                              />
                            </ListItemSecondaryAction>
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
        stixCoreRelationships(
          fromId: $fromId
          fromRole: $fromRole
          toTypes: $toTypes
          relationship_type: $relationship_type
          first: $first
          orderBy: $orderBy
          orderMode: $orderMode
        ) {
          edges {
            node {
              id
              description
              start_time
              stop_time
              to {
                ... on BasicObject {
                  id
                  entity_type
                }
                ... on AttackPattern {
                  name
                  x_mitre_id
                  killChainPhases {
                    edges {
                      node {
                        id
                        phase_name
                        x_opencti_order
                      }
                    }
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
                ... on Country {
                  name
                }
                ... on Region {
                  name
                }
                ... on Malware {
                  name
                  killChainPhases {
                    edges {
                      node {
                        id
                        phase_name
                        x_opencti_order
                      }
                    }
                  }
                }
                ... on ThreatActor {
                  name
                }
                ... on Tool {
                  name
                  killChainPhases {
                    edges {
                      node {
                        id
                        phase_name
                        x_opencti_order
                      }
                    }
                  }
                }
                ... on Vulnerability {
                  name
                }
                ... on Incident {
                  name
                }
              }
              killChainPhases {
                edges {
                  node {
                    id
                    phase_name
                    x_opencti_order
                  }
                }
              }
              objectMarking {
                edges {
                  node {
                    id
                    definition
                    x_opencti_color
                  }
                }
              }
            }
          }
        }
      }
    `,
  },
  stixDomainObjectThreatKnowledgeStixCoreRelationshipsQuery,
);

export default compose(
  inject18n,
  withStyles(styles),
)(StixDomainObjectGlobalKillChain);
