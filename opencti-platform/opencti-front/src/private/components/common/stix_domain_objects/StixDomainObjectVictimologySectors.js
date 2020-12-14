import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Link } from 'react-router-dom';
import Markdown from 'react-markdown';
import {
  compose,
  pipe,
  map,
  assoc,
  uniq,
  indexBy,
  prop,
  values,
  take,
  filter,
  pathOr,
  head,
  pluck,
  reduce,
  concat,
  sortWith,
  ascend,
  descend,
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
import { Domain, ExpandLess, ExpandMore } from '@material-ui/icons';
import { createRefetchContainer } from 'react-relay';
import { yearFormat } from '../../../../utils/Time';
import inject18n from '../../../../components/i18n';
import StixCoreRelationshipPopover from '../stix_core_relationships/StixCoreRelationshipPopover';
import StixCoreRelationshipCreationFromEntity from '../stix_core_relationships/StixCoreRelationshipCreationFromEntity';
import ItemYears from '../../../../components/ItemYears';
import SearchInput from '../../../../components/SearchInput';
import Security, { KNOWLEDGE_KNUPDATE } from '../../../../utils/Security';
import ItemMarking from '../../../../components/ItemMarking';
import ItemIcon from '../../../../components/ItemIcon';

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
  subnested: {
    paddingLeft: theme.spacing(8),
  },
});

class StixDomainObjectVictimologySectorsComponent extends Component {
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
          : true,
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

    const unknownSectorId = 'a8c03ed6-cc9e-444d-9146-66c64220fff9';
    const concatAll = reduce(concat, []);

    // Extract all sectors
    const sectors = pipe(
      filter(
        (n) => n.node.to.entity_type === 'Sector' && !n.node.to.isSubSector,
      ),
      map((n) => ({
        id: n.node.to.id,
        name: n.node.to.name,
        subSectors: {},
        relations: [],
      })),
    )(data.stixCoreRelationships.edges);
    const subSectors = pipe(
      filter(
        (n) => n.node.to.entity_type === 'Sector' && n.node.to.isSubSector,
      ),
      map((n) => ({
        id: n.node.to.id,
        name: n.node.to.name,
        parentSectors: map(
          (o) => ({
            id: o.node.id,
            name: o.node.name,
            subSectors: {},
            relations: [],
          }),
          n.node.to.parentSectors.edges,
        ),
        relations: [],
      })),
    )(data.stixCoreRelationships.edges);
    const subSectorsParentSectors = concatAll(
      pluck('parentSectors', subSectors),
    );
    const organizations = pipe(
      filter((n) => n.node.to.entity_type === 'Organization'),
      map((n) => ({
        id: n.node.to.id,
        name: n.node.to.name,
        sectors: map(
          (o) => ({
            id: o.node.id,
            name: o.node.name,
            isSubSector: o.node.isSubSector,
            subSectors: {},
            parentSectors: map(
              (p) => ({
                id: p.node.id,
                name: p.node.name,
                subSectors: {},
                relations: [],
              }),
              o.node.parentSectors.edges,
            ),
            relations: [],
          }),
          n.node.to.sectors.edges,
        ),
        relations: [],
      })),
    )(data.stixCoreRelationships.edges);
    const organizationsSectors = concatAll(pluck('sectors', organizations));
    const organizationsTopLevelSectors = filter(
      (n) => !n.isSubSector,
      organizationsSectors,
    );
    const organizationsParentSectors = concatAll(
      pluck('parentSectors', organizationsSectors),
    );

    const finalSectors = pipe(
      concat(subSectorsParentSectors),
      concat(organizationsTopLevelSectors),
      concat(organizationsParentSectors),
      uniq,
      indexBy(prop('id')),
    )(sectors);
    for (const subSector of subSectors) {
      for (const parentSector of subSector.parentSectors) {
        finalSectors[parentSector.id].subSectors[subSector.id] = subSector;
      }
    }
    for (const organizationSector of organizationsSectors) {
      for (const parentSector of organizationSector.parentSectors) {
        finalSectors[parentSector.id].subSectors[
          organizationSector.id
        ] = organizationSector;
      }
    }
    for (const stixCoreRelationshipEdge of data.stixCoreRelationships.edges) {
      let stixCoreRelationship = stixCoreRelationshipEdge.node;
      stixCoreRelationship = assoc(
        'startTimeYear',
        yearFormat(stixCoreRelationship.start_time),
        stixCoreRelationship,
      );
      stixCoreRelationship = assoc(
        'stopTimeYear',
        yearFormat(stixCoreRelationship.stop_time),
        stixCoreRelationship,
      );
      stixCoreRelationship = assoc(
        'years',
        stixCoreRelationship.startTimeYear === stixCoreRelationship.stopTimeYear
          ? stixCoreRelationship.startTimeYear
          : `${stixCoreRelationship.startTimeYear} - ${stixCoreRelationship.stopTimeYear}`,
        stixCoreRelationship,
      );
      if (stixCoreRelationship.to.entity_type === 'Sector') {
        if (stixCoreRelationship.to.isSubSector) {
          const parentSectorId = head(
            stixCoreRelationship.to.parentSectors.edges,
          ).node.id;
          finalSectors[parentSectorId].subSectors[
            stixCoreRelationship.to.id
          ].relations.push(stixCoreRelationship);
        } else {
          finalSectors[stixCoreRelationship.to.id].relations.push(
            stixCoreRelationship,
          );
        }
      }
      if (stixCoreRelationship.to.entity_type === 'Organization') {
        if (stixCoreRelationship.to.sectors.edges.length > 0) {
          const sector = head(stixCoreRelationship.to.sectors.edges).node;
          if (sector.isSubSector) {
            const parentSectorId = head(sector.parentSectors.edges).node.id;
            finalSectors[parentSectorId].subSectors[sector.id].relations.push(
              stixCoreRelationship,
            );
          } else {
            finalSectors[sector.id].relations.push(stixCoreRelationship);
          }
        } else {
          if (!(unknownSectorId in finalSectors)) {
            finalSectors[unknownSectorId] = {
              id: unknownSectorId,
              name: t('Unknown'),
              relations: [],
            };
          }
          finalSectors[unknownSectorId].relations.push(stixCoreRelationship);
        }
      }
    }
    const orderedFinalSectors = pipe(
      values,
      sortWith([ascend(prop('name'))]),
    )(finalSectors);
    return (
      <div>
        <SearchInput variant="small" onSubmit={this.handleSearch.bind(this)} />
        <div className={classes.container} id="container">
          <List id="test">
            {orderedFinalSectors.map((sector) => {
              const orderedRelations = pipe(
                values,
                sortWith([descend(prop('years'))]),
              )(sector.relations);
              const orderedSubSectors = pipe(
                values,
                sortWith([ascend(prop('name'))]),
              )(sector.subSectors);
              return (
                <div key={sector.id}>
                  <ListItem
                    button={true}
                    divider={true}
                    onClick={this.handleToggleLine.bind(this, sector.id)}
                  >
                    <ListItemIcon>
                      <Domain role="img" />
                    </ListItemIcon>
                    <ListItemText primary={sector.name} />
                    <ListItemSecondaryAction>
                      <IconButton
                        onClick={this.handleToggleLine.bind(this, sector.id)}
                        aria-haspopup="true"
                      >
                        {this.state.expandedLines[sector.id] === true ? (
                          <ExpandLess />
                        ) : (
                          <ExpandMore />
                        )}
                      </IconButton>
                    </ListItemSecondaryAction>
                  </ListItem>
                  <Collapse in={this.state.expandedLines[sector.id] === true}>
                    <List>
                      {orderedRelations.map((stixCoreRelationship) => {
                        const link = `${entityLink}/relations/${stixCoreRelationship.id}`;
                        return (
                          <ListItem
                            key={stixCoreRelationship.id}
                            classes={{ root: classes.nested }}
                            divider={true}
                            button={true}
                            dense={true}
                            component={Link}
                            to={link}
                          >
                            <ListItemIcon className={classes.itemIcon}>
                              <ItemIcon
                                type={stixCoreRelationship.to.entity_type}
                              />
                            </ListItemIcon>
                            <ListItemText
                              primary={
                                stixCoreRelationship.to.id === sector.id ? (
                                  <em>
                                    {t('Direct targeting of this sector')}
                                  </em>
                                ) : (
                                  stixCoreRelationship.to.name
                                )
                              }
                              secondary={
                                // eslint-disable-next-line no-nested-ternary
                                stixCoreRelationship.description
                                && stixCoreRelationship.description.length > 0 ? (
                                  <Markdown
                                    className="markdown"
                                    source={stixCoreRelationship.description}
                                  />
                                  ) : (
                                    t('No description of this targeting')
                                  )
                              }
                            />
                            {take(
                              1,
                              pathOr(
                                [],
                                ['markingDefinitions', 'edges'],
                                stixCoreRelationship,
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
                              years={stixCoreRelationship.years}
                            />
                            <ListItemSecondaryAction>
                              <StixCoreRelationshipPopover
                                stixCoreRelationshipId={stixCoreRelationship.id}
                                paginationOptions={paginationOptions}
                                onDelete={this.props.relay.refetch.bind(this)}
                              />
                            </ListItemSecondaryAction>
                          </ListItem>
                        );
                      })}
                      {orderedSubSectors.map((subsector) => {
                        const orderedSubRelations = pipe(
                          values,
                          sortWith([descend(prop('years'))]),
                        )(subsector.relations);
                        return (
                          <div key={subsector.id}>
                            <ListItem
                              button={true}
                              divider={true}
                              classes={{ root: classes.nested }}
                              onClick={this.handleToggleLine.bind(
                                this,
                                subsector.id,
                              )}
                            >
                              <ListItemIcon>
                                <Domain role="img" />
                              </ListItemIcon>
                              <ListItemText primary={subsector.name} />
                              <ListItemSecondaryAction>
                                <IconButton
                                  onClick={this.handleToggleLine.bind(
                                    this,
                                    subsector.id,
                                  )}
                                  aria-haspopup="true"
                                >
                                  {this.state.expandedLines[subsector.id]
                                  === true ? (
                                    <ExpandLess />
                                    ) : (
                                    <ExpandMore />
                                    )}
                                </IconButton>
                              </ListItemSecondaryAction>
                            </ListItem>
                            <Collapse
                              in={
                                this.state.expandedLines[subsector.id] === true
                              }
                            >
                              <List>
                                {orderedSubRelations.map(
                                  (stixCoreRelationship) => {
                                    const link = `${entityLink}/relations/${stixCoreRelationship.id}`;
                                    return (
                                      <ListItem
                                        key={stixCoreRelationship.id}
                                        classes={{ root: classes.subnested }}
                                        divider={true}
                                        button={true}
                                        dense={true}
                                        component={Link}
                                        to={link}
                                      >
                                        <ListItemIcon
                                          className={classes.itemIcon}
                                        >
                                          <ItemIcon
                                            type={
                                              stixCoreRelationship.to
                                                .entity_type
                                            }
                                          />
                                        </ListItemIcon>
                                        <ListItemText
                                          primary={
                                            stixCoreRelationship.to.id
                                            === subsector.id ? (
                                              <em>
                                                {t(
                                                  'Direct targeting of this sector',
                                                )}
                                              </em>
                                              ) : (
                                                stixCoreRelationship.to.name
                                              )
                                          }
                                          secondary={
                                            // eslint-disable-next-line no-nested-ternary
                                            stixCoreRelationship.description
                                            && stixCoreRelationship.description
                                              .length > 0 ? (
                                              <Markdown
                                                className="markdown"
                                                source={
                                                  stixCoreRelationship.description
                                                }
                                              />
                                              ) : stixCoreRelationship.inferred ? (
                                              <i>
                                                {t('This relation is inferred')}
                                              </i>
                                              ) : (
                                                t(
                                                  'No description of this targeting',
                                                )
                                              )
                                          }
                                        />
                                        {take(
                                          1,
                                          pathOr(
                                            [],
                                            ['markingDefinitions', 'edges'],
                                            stixCoreRelationship,
                                          ),
                                        ).map((markingDefinition) => (
                                          <ItemMarking
                                            key={markingDefinition.node.id}
                                            variant="inList"
                                            label={
                                              markingDefinition.node.definition
                                            }
                                            color={
                                              markingDefinition.node
                                                .x_opencti_color
                                            }
                                          />
                                        ))}
                                        <ItemYears
                                          variant="inList"
                                          years={stixCoreRelationship.years}
                                        />
                                        <ListItemSecondaryAction>
                                          <StixCoreRelationshipPopover
                                            stixCoreRelationshipId={
                                              stixCoreRelationship.id
                                            }
                                            paginationOptions={
                                              paginationOptions
                                            }
                                            onDelete={this.props.relay.refetch.bind(
                                              this,
                                            )}
                                          />
                                        </ListItemSecondaryAction>
                                      </ListItem>
                                    );
                                  },
                                )}
                              </List>
                            </Collapse>
                          </div>
                        );
                      })}
                    </List>
                  </Collapse>
                </div>
              );
            })}
          </List>
        </div>
        <Security needs={[KNOWLEDGE_KNUPDATE]}>
          <StixCoreRelationshipCreationFromEntity
            entityId={stixDomainObjectId}
            isRelationReversed={false}
            paddingRight={220}
            onCreate={this.props.relay.refetch.bind(this)}
            targetStixDomainObjectTypes={['Sector', 'Organization']}
            allowedRelationshipTypes={['targets']}
            paginationOptions={paginationOptions}
          />
        </Security>
      </div>
    );
  }
}

StixDomainObjectVictimologySectorsComponent.propTypes = {
  stixDomainObjectId: PropTypes.string,
  data: PropTypes.object,
  entityLink: PropTypes.string,
  paginationOptions: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

export const stixDomainObjectVictimologySectorsStixCoreRelationshipsQuery = graphql`
  query StixDomainObjectVictimologySectorsStixCoreRelationshipsQuery(
    $fromId: String
    $toTypes: [String]
    $relationship_type: String
    $first: Int
  ) {
    ...StixDomainObjectVictimologySectors_data
  }
`;

const StixDomainObjectVictimologySectorsSectorLines = createRefetchContainer(
  StixDomainObjectVictimologySectorsComponent,
  {
    data: graphql`
      fragment StixDomainObjectVictimologySectors_data on Query {
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
                ... on Organization {
                  name
                  sectors {
                    edges {
                      node {
                        id
                        name
                        isSubSector
                        parentSectors {
                          edges {
                            node {
                              id
                              name
                            }
                          }
                        }
                      }
                    }
                  }
                }
                ... on Sector {
                  name
                  isSubSector
                  parentSectors {
                    edges {
                      node {
                        id
                        name
                      }
                    }
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
  stixDomainObjectVictimologySectorsStixCoreRelationshipsQuery,
);

export default compose(
  inject18n,
  withStyles(styles),
)(StixDomainObjectVictimologySectorsSectorLines);
