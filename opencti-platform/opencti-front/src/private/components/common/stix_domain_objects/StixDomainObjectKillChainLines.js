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
  descend,
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
import { Launch, LockPattern } from 'mdi-material-ui';
import { ExpandLess, ExpandMore } from '@material-ui/icons';
import { createRefetchContainer } from 'react-relay';
import { yearFormat } from '../../../../utils/Time';
import inject18n from '../../../../components/i18n';
import StixCoreRelationshipPopover from '../stix_core_relationships/StixCoreRelationshipPopover';
import StixCoreRelationshipCreationFromEntity from '../stix_core_relationships/StixCoreRelationshipCreationFromEntity';
import ItemYears from '../../../../components/ItemYears';
import SearchInput from '../../../../components/SearchInput';
import Security, { KNOWLEDGE_KNUPDATE } from '../../../../utils/Security';
import ItemMarking from '../../../../components/ItemMarking';

const styles = (theme) => ({
  container: {
    paddingBottom: 70,
  },
  itemIcon: {
    color: theme.palette.primary.main,
  },
  nested: {
    paddingLeft: theme.spacing(4),
  },
});

class StixDomainObjectKillChainLinesComponent extends Component {
  constructor(props) {
    super(props);
    this.state = { expandedLines: {}, searchTerm: '' };
  }

  handleSearch(value) {
    this.setState({ searchTerm: value });
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
      t,
      classes,
      data,
      entityLink,
      paginationOptions,
      stixDomainObjectId,
    } = this.props;
    // Extract all kill chain phases
    const killChainPhases = pipe(
      // eslint-disable-next-line no-nested-ternary
      map((n) => (n.node.killChainPhases.edges.length > 0
        ? n.node.killChainPhases.edges[0].node
        : n.node.to.killChainPhases.edges.length > 0
          ? n.node.to.killChainPhases.edges[0].node
          : { id: 'unknown', phase_name: t('Unknown'), x_opencti_order: 99 })),
      uniq,
      indexBy(prop('id')),
    )(data.stixCoreRelationships.edges);
    const stixCoreRelationships = pipe(
      map((n) => n.node),
      map((n) => assoc('startTimeYear', yearFormat(n.start_time), n)),
      map((n) => assoc('stopTimeYear', yearFormat(n.stop_time), n)),
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
        n.killChainPhases.edges.length > 0
          ? n.killChainPhases.edges[0].node
          : n.to.killChainPhases.edges.length > 0
            ? n.to.killChainPhases.edges[0].node
            : { id: 'unknown', phase_name: t('Unknown'), x_opencti_order: 99 },
        n,
      )),
      sortWith([descend(prop('years'))]),
      groupBy(path(['killChainPhase', 'id'])),
      mapObjIndexed((value, key) => assoc('attackPatterns', value, killChainPhases[key])),
      values,
      sortWith([ascend(prop('x_opencti_order'))]),
    )(data.stixCoreRelationships.edges);
    return (
      <div>
        <SearchInput variant="small" onSubmit={this.handleSearch.bind(this)} />
        <div className={classes.container} id="container">
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
                    {stixCoreRelationship.attackPatterns.map(
                      (attackPattern) => {
                        const link = `${entityLink}/relations/${attackPattern.id}`;
                        return (
                          <ListItem
                            key={attackPattern.id}
                            classes={{ root: classes.nested }}
                            divider={true}
                            button={true}
                            dense={true}
                            component={Link}
                            to={link}
                          >
                            <ListItemIcon>
                              <LockPattern color="primary" role="img" />
                            </ListItemIcon>
                            <ListItemText
                              primary={
                                <span>
                                  <strong>{attackPattern.to.x_mitre_id}</strong>{' '}
                                  - {attackPattern.to.name}
                                </span>
                              }
                              secondary={
                                attackPattern.description
                                && attackPattern.description.length > 0 ? (
                                  <Markdown
                                    className="markdown"
                                    source={attackPattern.description}
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
                                attackPattern,
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
                              years={attackPattern.years}
                            />
                            <ListItemSecondaryAction>
                              <StixCoreRelationshipPopover
                                stixCoreRelationshipId={attackPattern.id}
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
        <Security needs={[KNOWLEDGE_KNUPDATE]}>
          <StixCoreRelationshipCreationFromEntity
            entityId={stixDomainObjectId}
            isRelationReversed={false}
            paddingRight={220}
            onCreate={this.props.relay.refetch.bind(this)}
            targetStixDomainObjectTypes={['Attack-Pattern']}
            paginationOptions={paginationOptions}
          />
        </Security>
      </div>
    );
  }
}

StixDomainObjectKillChainLinesComponent.propTypes = {
  stixDomainObjectId: PropTypes.string,
  data: PropTypes.object,
  entityLink: PropTypes.string,
  paginationOptions: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

export const stixDomainObjectKillChainLinesStixCoreRelationshipsQuery = graphql`
  query StixDomainObjectKillChainLinesStixCoreRelationshipsQuery(
    $fromId: String
    $toTypes: [String]
    $relationship_type: String
    $first: Int
  ) {
    ...StixDomainObjectKillChainLines_data
  }
`;

const StixDomainObjectKillChainLines = createRefetchContainer(
  StixDomainObjectKillChainLinesComponent,
  {
    data: graphql`
      fragment StixDomainObjectKillChainLines_data on Query {
        stixCoreRelationships(
          fromId: $fromId
          toTypes: $toTypes
          relationship_type: $relationship_type
          first: $first
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
                ... on BasicRelationship {
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
                }
                ... on ThreatActor {
                  name
                }
                ... on Tool {
                  name
                }
                ... on Vulnerability {
                  name
                }
                ... on XOpenCTIIncident {
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
  stixDomainObjectKillChainLinesStixCoreRelationshipsQuery,
);

export default compose(
  inject18n,
  withStyles(styles),
)(StixDomainObjectKillChainLines);
