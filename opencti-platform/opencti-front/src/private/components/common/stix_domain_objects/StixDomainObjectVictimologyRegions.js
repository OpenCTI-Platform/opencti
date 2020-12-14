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
  pluck,
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
import {
  ExpandLess, ExpandMore, Map, Flag,
} from '@material-ui/icons';
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

class StixDomainObjectVictimologyRegionsComponent extends Component {
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

    const unknownRegionId = 'fe15f901-07eb-4b28-b5a4-54f6d589a337';
    const unknownCountryId = '5b1e93ff-9b3d-4ab5-b1bd-3fd95dc17626';

    // Extract all regions
    const regions = pipe(
      filter((n) => n.node.to.entity_type === 'Region'),
      map((n) => ({
        id: n.node.to.id,
        name: n.node.to.name,
        countries: {},
        relations: [],
      })),
    )(data.stixCoreRelationships.edges);
    const countries = pipe(
      filter((n) => n.node.to.entity_type === 'Country'),
      map((n) => ({
        id: n.node.to.id,
        name: n.node.to.name,
        cities: {},
        region: n.node.to.region
          ? {
            id: n.node.to.region.id,
            name: n.node.to.region.name,
            countries: {},
            relations: [],
          }
          : null,
        relations: [],
      })),
    )(data.stixCoreRelationships.edges);
    const countriesRegions = filter(
      (n) => n !== null,
      pluck('region', countries),
    );
    const cities = pipe(
      filter((n) => n.node.to.entity_type === 'City'),
      map((n) => ({
        id: n.node.to.id,
        name: n.node.to.name,
        country: n.node.to.country
          ? {
            id: n.node.to.country.id,
            name: n.node.to.country.name,
            region: n.node.to.country.region
              ? {
                id: n.node.to.country.region.id,
                name: n.node.to.country.region.name,
                countries: {},
              }
              : null,
            cities: {},
            relations: [],
          }
          : null,
        relations: [],
      })),
    )(data.stixCoreRelationships.edges);
    const citiesCountries = filter((n) => n !== null, pluck('country', cities));
    const citiesCountriesRegions = filter(
      (n) => n !== null,
      pluck('region', citiesCountries),
    );
    const finalRegions = pipe(
      concat(countriesRegions),
      concat(citiesCountriesRegions),
      uniq,
      indexBy(prop('id')),
    )(regions);
    const finalCountries = pipe(
      concat(citiesCountries),
      uniq,
      indexBy(prop('id')),
    )(countries);
    for (const country of values(finalCountries)) {
      if (country.region) {
        finalRegions[country.region.id].countries[country.id] = country;
      }
    }
    for (const city of cities) {
      if (city.country) {
        if (city.country.region) {
          finalRegions[city.country.region.id].countries[
            city.country.id
          ].cities[city.id] = city;
        }
      }
    }
    for (const stixCoreRelationshipEdge of data.stixCoreRelationships.edges) {
      let stixCoreRelationship = stixCoreRelationshipEdge.node;
      stixCoreRelationship = assoc(
        'startTimeYear',
        yearFormat(stixCoreRelationship.first_seen),
        stixCoreRelationship,
      );
      stixCoreRelationship = assoc(
        'stopTimeYear',
        yearFormat(stixCoreRelationship.last_seen),
        stixCoreRelationship,
      );
      stixCoreRelationship = assoc(
        'years',
        stixCoreRelationship.startTimeYear === stixCoreRelationship.stopTimeYear
          ? stixCoreRelationship.startTimeYear
          : `${stixCoreRelationship.startTimeYear} - ${stixCoreRelationship.stopTimeYear}`,
        stixCoreRelationship,
      );
      if (stixCoreRelationship.to.entity_type === 'Region') {
        finalRegions[stixCoreRelationship.to.id].relations.push(
          stixCoreRelationship,
        );
      }
      if (stixCoreRelationship.to.entity_type === 'Country') {
        if (stixCoreRelationship.to.region) {
          finalRegions[stixCoreRelationship.to.region.id].countries[
            stixCoreRelationship.to.id
          ].relations.push(stixCoreRelationship);
        } else {
          if (!(unknownRegionId in finalRegions)) {
            finalRegions[unknownRegionId] = {
              id: unknownRegionId,
              name: t('Unknown'),
              countries: {},
              relations: [],
            };
          }
          finalRegions[unknownRegionId].relations.push(stixCoreRelationship);
        }
      }
      if (stixCoreRelationship.to.entity_type === 'City') {
        if (stixCoreRelationship.to.country) {
          if (stixCoreRelationship.to.country.region) {
            finalRegions[stixCoreRelationship.to.country.region.id].countries[
              stixCoreRelationship.to.country.id
            ].cities[stixCoreRelationship.to.id].relations.push(
              stixCoreRelationship,
            );
          } else {
            if (!(unknownRegionId in finalRegions)) {
              finalRegions[unknownRegionId] = {
                id: unknownRegionId,
                name: t('Unknown'),
                countries: {},
                relations: [],
              };
            }
            if (
              !(
                stixCoreRelationship.to.country.id
                in finalRegions[unknownRegionId]
              )
            ) {
              finalRegions[unknownRegionId].countries[
                stixCoreRelationship.to.country.id
              ] = {
                id: stixCoreRelationship.to.country.id,
                name: stixCoreRelationship.to.country.name,
                cities: {},
                relations: [],
              };
            }
            finalRegions[unknownRegionId].countries[
              stixCoreRelationship.to.country.id
            ].relations.push(stixCoreRelationship);
          }
        } else {
          if (!(unknownRegionId in finalRegions)) {
            finalRegions[unknownRegionId] = {
              id: unknownRegionId,
              name: t('Unknown'),
              countries: {},
              relations: [],
            };
          }
          if (!(unknownCountryId in finalRegions[unknownRegionId].countries)) {
            finalRegions[unknownRegionId].countries[unknownCountryId] = {
              id: unknownCountryId,
              name: t('Unknown'),
              cities: {},
              relations: [],
            };
          }
          finalRegions[unknownRegionId].countries[
            unknownCountryId
          ].relations.push(stixCoreRelationship);
        }
      }
    }

    const orderedFinalRegions = pipe(
      values,
      sortWith([ascend(prop('name'))]),
    )(finalRegions);
    return (
      <div style={{ marginTop: -10 }}>
        <SearchInput variant="small" onSubmit={this.handleSearch.bind(this)} />
        <div className={classes.container} id="container">
          <List id="test">
            {orderedFinalRegions.map((region) => {
              const orderedRelations = pipe(
                values,
                sortWith([descend(prop('years'))]),
              )(region.relations);
              const orderedCountries = pipe(
                values,
                sortWith([ascend(prop('name'))]),
              )(region.countries);
              return (
                <div key={region.id}>
                  <ListItem
                    button={true}
                    divider={true}
                    onClick={this.handleToggleLine.bind(this, region.id)}
                  >
                    <ListItemIcon>
                      <Map role="img" />
                    </ListItemIcon>
                    <ListItemText primary={region.name} />
                    <ListItemSecondaryAction>
                      <IconButton
                        onClick={this.handleToggleLine.bind(this, region.id)}
                        aria-haspopup="true"
                      >
                        {this.state.expandedLines[region.id] === true ? (
                          <ExpandLess />
                        ) : (
                          <ExpandMore />
                        )}
                      </IconButton>
                    </ListItemSecondaryAction>
                  </ListItem>
                  <Collapse in={this.state.expandedLines[region.id] === true}>
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
                                stixCoreRelationship.to.id === region.id ? (
                                  <em>
                                    {t('Direct targeting of this region')}
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
                              country
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
                      {orderedCountries.map((country) => {
                        const orderedSubRelations = pipe(
                          values,
                          sortWith([descend(prop('years'))]),
                        )(country.relations);
                        const orderedCities = pipe(
                          values,
                          sortWith([ascend(prop('name'))]),
                        )(country.cities);
                        return (
                          <div key={country.id}>
                            <ListItem
                              button={true}
                              divider={true}
                              classes={{ root: classes.nested }}
                              onClick={this.handleToggleLine.bind(
                                this,
                                country.id,
                              )}
                            >
                              <ListItemIcon>
                                <Flag role="img" />
                              </ListItemIcon>
                              <ListItemText primary={country.name} />
                              <ListItemSecondaryAction>
                                <IconButton
                                  onClick={this.handleToggleLine.bind(
                                    this,
                                    country.id,
                                  )}
                                  aria-haspopup="true"
                                >
                                  {this.state.expandedLines[country.id]
                                  === true ? (
                                    <ExpandLess />
                                    ) : (
                                    <ExpandMore />
                                    )}
                                </IconButton>
                              </ListItemSecondaryAction>
                            </ListItem>
                            <Collapse
                              in={this.state.expandedLines[country.id] === true}
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
                                            === country.id ? (
                                              <em>
                                                {t(
                                                  'Direct targeting of this country',
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
                                {orderedCities.map((city) => {
                                  const orderedSubSubRelations = pipe(
                                    values,
                                    sortWith([descend(prop('years'))]),
                                  )(city.relations);
                                  return (
                                    <div key={city.id}>
                                      {orderedSubSubRelations.map(
                                        (stixCoreRelationship) => {
                                          const link = `${entityLink}/relations/${stixCoreRelationship.id}`;
                                          return (
                                            <ListItem
                                              key={stixCoreRelationship.id}
                                              classes={{
                                                root: classes.subnested,
                                              }}
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
                                                  === country.id ? (
                                                    <em>
                                                      {t(
                                                        'Direct targeting of this country',
                                                      )}
                                                    </em>
                                                    ) : (
                                                      stixCoreRelationship.to.name
                                                    )
                                                }
                                                secondary={
                                                  // eslint-disable-next-line no-nested-ternary
                                                  stixCoreRelationship.description
                                                  && stixCoreRelationship
                                                    .description.length > 0 ? (
                                                    <Markdown
                                                      className="markdown"
                                                      source={
                                                        stixCoreRelationship.description
                                                      }
                                                    />
                                                    ) : stixCoreRelationship.inferred ? (
                                                    <i>
                                                      {t(
                                                        'This relation is inferred',
                                                      )}
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
                                                  [
                                                    'markingDefinitions',
                                                    'edges',
                                                  ],
                                                  stixCoreRelationship,
                                                ),
                                              ).map((markingDefinition) => (
                                                <ItemMarking
                                                  key={
                                                    markingDefinition.node.id
                                                  }
                                                  variant="inList"
                                                  label={
                                                    markingDefinition.node
                                                      .definition
                                                  }
                                                  color={
                                                    markingDefinition.node
                                                      .x_opencti_color
                                                  }
                                                />
                                              ))}
                                              <ItemYears
                                                variant="inList"
                                                years={
                                                  stixCoreRelationship.years
                                                }
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
                                    </div>
                                  );
                                })}
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
            targetStixDomainObjectTypes={['Region', 'Country', 'City']}
            allowedRelationshipTypes={['targets']}
            paginationOptions={paginationOptions}
          />
        </Security>
      </div>
    );
  }
}

StixDomainObjectVictimologyRegionsComponent.propTypes = {
  stixDomainObjectId: PropTypes.string,
  data: PropTypes.object,
  entityLink: PropTypes.string,
  paginationOptions: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

export const stixDomainObjectVictimologyRegionsStixCoreRelationshipsQuery = graphql`
  query StixDomainObjectVictimologyRegionsStixCoreRelationshipsQuery(
    $fromId: String
    $toTypes: [String]
    $relationship_type: String
    $first: Int
  ) {
    ...StixDomainObjectVictimologyRegions_data
  }
`;

const StixDomainObjectVictimologyRegionsSectorLines = createRefetchContainer(
  StixDomainObjectVictimologyRegionsComponent,
  {
    data: graphql`
      fragment StixDomainObjectVictimologyRegions_data on Query {
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
                ... on City {
                  name
                  country {
                    id
                    name
                    region {
                      id
                      name
                    }
                  }
                }
                ... on Country {
                  name
                  region {
                    id
                    name
                  }
                }
                ... on Region {
                  name
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
  stixDomainObjectVictimologyRegionsStixCoreRelationshipsQuery,
);

export default compose(
  inject18n,
  withStyles(styles),
)(StixDomainObjectVictimologyRegionsSectorLines);
