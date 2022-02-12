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
import {
  ExpandLess,
  ExpandMore,
  LocalPlayOutlined,
  Flag,
} from '@mui/icons-material';
import remarkGfm from 'remark-gfm';
import remarkParse from 'remark-parse';
import Tooltip from '@mui/material/Tooltip';
import * as R from 'ramda';
import { AutoFix } from 'mdi-material-ui';
import { yearFormat } from '../../../../utils/Time';
import inject18n from '../../../../components/i18n';
import StixCoreRelationshipPopover from '../stix_core_relationships/StixCoreRelationshipPopover';
import ItemYears from '../../../../components/ItemYears';
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

class StixDomainObjectVictimologyRegionsList extends Component {
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
          : true,
        this.state.expandedLines,
      ),
    });
  }

  render() {
    const { t, classes, data, entityLink, paginationOptions, searchTerm } = this.props;
    const filterByKeyword = (n) => searchTerm === ''
      || n.name.toLowerCase().indexOf(searchTerm.toLowerCase()) !== -1
      || propOr('', 'countries_text', n)
        .toLowerCase()
        .indexOf(searchTerm.toLowerCase()) !== -1;
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
            countries_text: '',
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
        finalRegions[country.region.id].countries_text = `${
          finalRegions[country.region.id].countries_text
        } ${country.name}`;
      }
    }
    for (const city of cities) {
      if (city.country) {
        if (city.country.region) {
          finalRegions[city.country.region.id].countries[
            city.country.id
          ].cities[city.id] = city;
          finalRegions[city.country.region.id].countries_text = `${
            finalRegions[city.country.region.id].countries_text
          } ${city.name}`;
        }
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
      filter(filterByKeyword),
    )(finalRegions);
    return (
      <List>
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
                  <LocalPlayOutlined role="img" />
                </ListItemIcon>
                <ListItemText primary={region.name} />
                <ListItemSecondaryAction>
                  <IconButton
                    onClick={this.handleToggleLine.bind(this, region.id)}
                    aria-haspopup="true"
                    size="large"
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
                              <em>{t('Direct targeting of this region')}</em>
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
                          country
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
                              stixCoreRelationshipId={stixCoreRelationship.id}
                              paginationOptions={paginationOptions}
                              onDelete={this.props.handleDelete.bind(this)}
                            />
                          )}
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
                          onClick={this.handleToggleLine.bind(this, country.id)}
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
                              size="large"
                            >
                              {this.state.expandedLines[country.id] === true ? (
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
                            {orderedSubRelations.map((stixCoreRelationship) => {
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
                                  <ListItemIcon className={classes.itemIcon}>
                                    <ItemIcon
                                      type={stixCoreRelationship.to.entity_type}
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
                                      && stixCoreRelationship.description.length
                                        > 0 ? (
                                        <Markdown
                                          remarkPlugins={[
                                            remarkGfm,
                                            remarkParse,
                                          ]}
                                          parserOptions={{ commonmark: true }}
                                          className="markdown"
                                        >
                                          {stixCoreRelationship.description}
                                        </Markdown>
                                        ) : stixCoreRelationship.inferred ? (
                                        <i>{t('This relation is inferred')}</i>
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
                                      color={
                                        markingDefinition.node.x_opencti_color
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
                                        paginationOptions={paginationOptions}
                                        onDelete={this.props.handleDelete.bind(
                                          this,
                                        )}
                                      />
                                    )}
                                  </ListItemSecondaryAction>
                                </ListItem>
                              );
                            })}
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
                                              ['markingDefinitions', 'edges'],
                                              stixCoreRelationship,
                                            ),
                                          ).map((markingDefinition) => (
                                            <ItemMarking
                                              key={markingDefinition.node.id}
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
                                                onDelete={this.props.handleDelete.bind(
                                                  this,
                                                )}
                                              />
                                            )}
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
    );
  }
}

StixDomainObjectVictimologyRegionsList.propTypes = {
  handleDelete: PropTypes.func,
  searchTerm: PropTypes.string,
  data: PropTypes.object,
  entityLink: PropTypes.string,
  paginationOptions: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

export default compose(
  inject18n,
  withStyles(styles),
)(StixDomainObjectVictimologyRegionsList);
