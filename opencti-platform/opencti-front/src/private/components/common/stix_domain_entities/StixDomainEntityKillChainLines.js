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
} from 'ramda';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import List from '@material-ui/core/List';
import ListItem from '@material-ui/core/ListItem';
import ListItemText from '@material-ui/core/ListItemText';
import ListItemIcon from '@material-ui/core/ListItemIcon';
import ListItemSecondaryAction from '@material-ui/core/ListItemSecondaryAction';
import Collapse from '@material-ui/core/Collapse';
import { Launch, LockPattern } from 'mdi-material-ui';
import { ExpandLess, ExpandMore } from '@material-ui/icons';
import IconButton from '@material-ui/core/IconButton';
import { createRefetchContainer } from 'react-relay';
import inject18n from '../../../../components/i18n';
import StixRelationPopover from '../stix_relations/StixRelationPopover';
import StixRelationCreationFromEntity from '../stix_relations/StixRelationCreationFromEntity';

const styles = (theme) => ({
  itemIcon: {
    color: theme.palette.primary.main,
  },
  nested: {
    paddingLeft: theme.spacing(4),
  },
});

class StixDomainEntityKillChainLinesComponent extends Component {
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
      t,
      classes,
      data,
      entityLink,
      paginationOptions,
      stixDomainEntityId,
    } = this.props;
    // Extract all kill chain phases
    const killChainPhases = pipe(
      map((n) => (n.node.killChainPhases.edges.length > 0
        ? n.node.killChainPhases.edges[0].node
        : n.node.to.killChainPhases.edges[0].node)),
      uniq,
      indexBy(prop('id')),
    )(data.stixRelations.edges);
    const stixRelations = pipe(
      map((n) => n.node),
      map((n) => assoc(
        'killChainPhase',
        n.killChainPhases.edges.length > 0
          ? n.killChainPhases.edges[0].node
          : n.to.killChainPhases.edges[0].node,
        n,
      )),
      groupBy(path(['killChainPhase', 'id'])),
      mapObjIndexed((value, key) => assoc('attackPatterns', value, killChainPhases[key])),
      values,
      sortWith([ascend(prop('phase_order'))]),
    )(data.stixRelations.edges);
    return (
      <div>
        <List>
          {stixRelations.map((stixRelation) => (
            <div key={stixRelation.id}>
              <ListItem
                button={true}
                divider={true}
                onClick={this.handleToggleLine.bind(this, stixRelation.id)}
              >
                <ListItemIcon classes={{ root: classes.itemIcon }}>
                  <Launch />
                </ListItemIcon>
                <ListItemText primary={stixRelation.phase_name} />
                <ListItemSecondaryAction>
                  <IconButton
                    onClick={this.handleToggleLine.bind(this, stixRelation.id)}
                    aria-haspopup="true"
                  >
                    {this.state.expandedLines[stixRelation.id] === false ? (
                      <ExpandMore />
                    ) : (
                      <ExpandLess />
                    )}
                  </IconButton>
                </ListItemSecondaryAction>
              </ListItem>
              <Collapse
                in={this.state.expandedLines[stixRelation.id] !== false}
              >
                <List>
                  {stixRelation.attackPatterns.map((attackPattern) => {
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
                        <ListItemIcon classes={{ root: classes.itemIcon }}>
                          <LockPattern />
                        </ListItemIcon>
                        <ListItemText
                          primary={`${attackPattern.to.external_id} - ${attackPattern.to.name}`}
                          secondary={
                            <Markdown
                              className="markdown"
                              source={
                                attackPattern.description
                                && attackPattern.description.length > 0
                                  ? attackPattern.description
                                  : t('No description of this usage')
                              }
                            />
                          }
                        />
                        <ListItemSecondaryAction>
                          <StixRelationPopover
                            stixRelationId={attackPattern.id}
                            paginationOptions={paginationOptions}
                            onDelete={this.props.relay.refetch.bind(this)}
                          />
                        </ListItemSecondaryAction>
                      </ListItem>
                    );
                  })}
                </List>
              </Collapse>
            </div>
          ))}
        </List>
        <StixRelationCreationFromEntity
          entityId={stixDomainEntityId}
          isFrom={true}
          onCreate={this.props.relay.refetch.bind(this)}
          targetEntityTypes={['Attack-Pattern']}
          paginationOptions={paginationOptions}
        />
      </div>
    );
  }
}

StixDomainEntityKillChainLinesComponent.propTypes = {
  stixDomainEntityId: PropTypes.string,
  data: PropTypes.object,
  entityLink: PropTypes.string,
  paginationOptions: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

export const stixDomainEntityKillChainLinesStixRelationsQuery = graphql`
  query StixDomainEntityKillChainLinesStixRelationsQuery(
    $fromId: String
    $toTypes: [String]
    $relationType: String
    $inferred: Boolean
    $first: Int
  ) {
    ...StixDomainEntityKillChainLines_data
  }
`;

const StixDomainEntityKillChainLines = createRefetchContainer(
  StixDomainEntityKillChainLinesComponent,
  {
    data: graphql`
      fragment StixDomainEntityKillChainLines_data on Query {
        stixRelations(
          fromId: $fromId
          toTypes: $toTypes
          relationType: $relationType
          inferred: $inferred
          first: $first
        ) {
          edges {
            node {
              id
              description
              first_seen
              last_seen
              to {
                id
                name
                ... on AttackPattern {
                  external_id
                  killChainPhases {
                    edges {
                      node {
                        id
                        phase_name
                        phase_order
                      }
                    }
                  }
                }
              }
              killChainPhases {
                edges {
                  node {
                    id
                    phase_name
                    phase_order
                  }
                }
              }
            }
          }
        }
      }
    `,
  },
  stixDomainEntityKillChainLinesStixRelationsQuery,
);

export default compose(
  inject18n,
  withStyles(styles),
)(StixDomainEntityKillChainLines);
