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
  propOr,
} from 'ramda';
import withStyles from '@mui/styles/withStyles';
import IconButton from '@mui/material/IconButton';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemText from '@mui/material/ListItemText';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemSecondaryAction from '@mui/material/ListItemSecondaryAction';
import Collapse from '@mui/material/Collapse';
import { Domain, ExpandLess, ExpandMore } from '@mui/icons-material';
import { graphql, createRefetchContainer } from 'react-relay';
import remarkGfm from 'remark-gfm';
import remarkParse from 'remark-parse';
import Tooltip from '@mui/material/Tooltip';
import * as R from 'ramda';
import { AutoFix } from 'mdi-material-ui';
import { yearFormat } from '../../../../utils/Time';
import inject18n from '../../../../components/i18n';
import StixCoreRelationshipPopover from '../stix_core_relationships/StixCoreRelationshipPopover';
import StixCoreRelationshipCreationFromEntity from '../stix_core_relationships/StixCoreRelationshipCreationFromEntity';
import ItemYears from '../../../../components/ItemYears';
import SearchInput from '../../../../components/SearchInput';
import Security, { KNOWLEDGE_KNUPDATE } from '../../../../utils/Security';
import ItemMarking from '../../../../components/ItemMarking';
import ItemIcon from '../../../../components/ItemIcon';
import ExportButtons from '../../../../components/ExportButtons';

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
  export: {
    float: 'right',
    marginTop: -10,
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
    const { searchTerm } = this.state;
    const {
      t,
      classes,
      data,
      entityLink,
      paginationOptions,
      stixDomainObjectId,
    } = this.props;
    const filterByKeyword = (n) => searchTerm === ''
      || n.name.toLowerCase().indexOf(searchTerm.toLowerCase()) !== -1
      || n.description.toLowerCase().indexOf(searchTerm.toLowerCase()) !== -1
      || propOr('', 'subsectors_text', n)
        .toLowerCase()
        .indexOf(searchTerm.toLowerCase()) !== -1;
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
        description: n.node.to.description,
        subSectors: {},
        subsectors_text: '',
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
        finalSectors[parentSector.id].subsectors_text = `${
          finalSectors[parentSector.id].subsectors_text
        } ${subSector.name} ${subSector.description}`;
      }
    }
    for (const organizationSector of organizationsSectors) {
      for (const parentSector of organizationSector.parentSectors) {
        finalSectors[parentSector.id].subSectors[organizationSector.id] = organizationSector;
        finalSectors[parentSector.id].subsectors_text = `${
          finalSectors[parentSector.id].subsectors_text
        } ${organizationSector.name} ${organizationSector.description}`;
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
            finalSectors[
              parentSectorId
            ].subsectors_text = `${finalSectors[parentSectorId].subsectors_text} ${stixCoreRelationship.to.name} ${stixCoreRelationship.to.description}`;
          } else {
            finalSectors[sector.id].relations.push(stixCoreRelationship);
            finalSectors[sector.id].subsectors_text = `${
              finalSectors[sector.id].subsectors_text
            } ${stixCoreRelationship.to.name} ${
              stixCoreRelationship.to.description
            }`;
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
      filter(filterByKeyword),
    )(finalSectors);
    return (
      <div>
        <SearchInput variant="small" onSubmit={this.handleSearch.bind(this)} />
        <div className={classes.export}>
          <ExportButtons domElementId="container" name={t('Victimology')} />
        </div>
        <div className="clearfix" />
        <div className={classes.container} id="container">
          <List>
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
                        size="large"
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
                                    remarkPlugins={[remarkGfm, remarkParse]}
                                    parserOptions={{ commonmark: true }}
                                    className="markdown"
                                  >
                                    {stixCoreRelationship.description}
                                  </Markdown>
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
                              {stixCoreRelationship.is_inferred ? (
                                <Tooltip
                                  title={
                                    t('Inferred knowledge based on the rule ')
                                    + R.head(
                                      stixCoreRelationship.x_opencti_inferences,
                                    ).rule.name
                                  }
                                >
                                  <AutoFix
                                    fontSize="small"
                                    style={{ marginLeft: -30 }}
                                  />
                                </Tooltip>
                              ) : (
                                <StixCoreRelationshipPopover
                                  stixCoreRelationshipId={
                                    stixCoreRelationship.id
                                  }
                                  paginationOptions={paginationOptions}
                                  onDelete={this.props.relay.refetch.bind(this)}
                                />
                              )}
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
                                  size="large"
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
                                                remarkPlugins={[
                                                  remarkGfm,
                                                  remarkParse,
                                                ]}
                                                parserOptions={{
                                                  commonmark: true,
                                                }}
                                                className="markdown"
                                              >
                                                {
                                                  stixCoreRelationship.description
                                                }
                                              </Markdown>
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
                                          {stixCoreRelationship.is_inferred ? (
                                            <Tooltip
                                              title={
                                                t(
                                                  'Inferred knowledge based on the rule ',
                                                )
                                                + R.head(
                                                  stixCoreRelationship.x_opencti_inferences,
                                                ).rule.name
                                              }
                                            >
                                              <AutoFix
                                                fontSize="small"
                                                style={{ marginLeft: -30 }}
                                              />
                                            </Tooltip>
                                          ) : (
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
                                          )}
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
    $relationship_type: [String]
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
              is_inferred
              x_opencti_inferences {
                rule {
                  id
                  name
                }
              }
              to {
                ... on BasicObject {
                  id
                  entity_type
                }
                ... on Organization {
                  name
                  description
                  sectors {
                    edges {
                      node {
                        id
                        name
                        description
                        isSubSector
                        parentSectors {
                          edges {
                            node {
                              id
                              name
                              description
                            }
                          }
                        }
                      }
                    }
                  }
                }
                ... on Sector {
                  name
                  description
                  isSubSector
                  parentSectors {
                    edges {
                      node {
                        id
                        name
                        description
                      }
                    }
                  }
                }
                ... on System {
                  name
                  description
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
