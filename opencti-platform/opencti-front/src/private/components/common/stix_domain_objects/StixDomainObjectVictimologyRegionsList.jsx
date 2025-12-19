import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Link } from 'react-router-dom';
import * as R from 'ramda';
import withStyles from '@mui/styles/withStyles';
import IconButton from '@common/button/IconButton';
import List from '@mui/material/List';
import ListItemText from '@mui/material/ListItemText';
import ListItemIcon from '@mui/material/ListItemIcon';
import Collapse from '@mui/material/Collapse';
import { ExpandLess, ExpandMore, Flag, LocalPlayOutlined } from '@mui/icons-material';
import Tooltip from '@mui/material/Tooltip';
import { AutoFix } from 'mdi-material-ui';
import { ListItemButton } from '@mui/material';
import ListItem from '@mui/material/ListItem';
import { yearFormat } from '../../../../utils/Time';
import inject18n from '../../../../components/i18n';
import StixCoreRelationshipPopover from '../stix_core_relationships/StixCoreRelationshipPopover';
import ItemYears from '../../../../components/ItemYears';
import ItemIcon from '../../../../components/ItemIcon';
import ItemMarkings from '../../../../components/ItemMarkings';
import MarkdownDisplay from '../../../../components/MarkdownDisplay';

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
      expandedLines: R.assoc(
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
      || R.propOr('', 'countries_text', n)
        .toLowerCase()
        .indexOf(searchTerm.toLowerCase()) !== -1;
    const unknownRegionId = 'fe15f901-07eb-4b28-b5a4-54f6d589a337';
    const unknownCountryId = '5b1e93ff-9b3d-4ab5-b1bd-3fd95dc17626';
    // Extract all regions
    const regions = R.pipe(
      R.filter((n) => n.node.to.entity_type === 'Region'),
      R.map((n) => ({
        id: n.node.to.id,
        name: n.node.to.name,
        countries: {},
        relations: [],
      })),
    )(data.stixCoreRelationships.edges);
    const countries = R.pipe(
      R.filter((n) => n.node.to.entity_type === 'Country'),
      R.map((n) => ({
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
    const countriesRegions = R.filter(
      (n) => n !== null,
      R.pluck('region', countries),
    );
    const cities = R.pipe(
      R.filter((n) => n.node.to.entity_type === 'City'),
      R.map((n) => ({
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
    const citiesCountries = R.filter(
      (n) => n !== null,
      R.pluck('country', cities),
    );
    const citiesCountriesRegions = R.filter(
      (n) => n !== null,
      R.pluck('region', citiesCountries),
    );
    const finalRegions = R.pipe(
      R.concat(countriesRegions),
      R.concat(citiesCountriesRegions),
      R.uniq,
      R.indexBy(R.prop('id')),
    )(regions);
    const finalCountries = R.pipe(
      R.concat(citiesCountries),
      R.uniq,
      R.indexBy(R.prop('id')),
    )(countries);
    for (const country of R.values(finalCountries)) {
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
      stixCoreRelationship = R.assoc(
        'startTimeYear',
        yearFormat(stixCoreRelationship.start_time),
        stixCoreRelationship,
      );
      stixCoreRelationship = R.assoc(
        'stopTimeYear',
        yearFormat(stixCoreRelationship.stop_time),
        stixCoreRelationship,
      );
      stixCoreRelationship = R.assoc(
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
    const orderedFinalRegions = R.pipe(
      R.values,
      R.sortWith([R.ascend(R.prop('name'))]),
      R.filter(filterByKeyword),
    )(finalRegions);
    return (
      <List>
        {orderedFinalRegions.map((region) => {
          const orderedRelations = R.pipe(
            R.values,
            R.sortWith([R.descend(R.prop('years'))]),
          )(region.relations);
          const orderedCountries = R.pipe(
            R.values,
            R.sortWith([R.ascend(R.prop('name'))]),
          )(region.countries);
          return (
            <div key={region.id}>
              <ListItem
                divider={true}
                disablePadding
                secondaryAction={(
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
                )}
              >
                <ListItemButton
                  onClick={this.handleToggleLine.bind(this, region.id)}
                >
                  <ListItemIcon>
                    <LocalPlayOutlined role="img" />
                  </ListItemIcon>
                  <ListItemText primary={region.name} />
                </ListItemButton>
              </ListItem>
              <Collapse in={this.state.expandedLines[region.id] === true}>
                <List>
                  {orderedRelations.map((stixCoreRelationship) => {
                    const link = `${entityLink}/relations/${stixCoreRelationship.id}`;
                    return (
                      <ListItem
                        key={stixCoreRelationship.id}
                        divider={true}
                        dense={true}
                        disablePadding
                        secondaryAction={stixCoreRelationship.is_inferred ? (
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
                      >
                        <ListItemButton
                          classes={{ root: classes.nested }}
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

                              stixCoreRelationship.description
                              && stixCoreRelationship.description.length > 0 ? (
                                    <MarkdownDisplay
                                      content={stixCoreRelationship.description}
                                      remarkGfmPlugin={true}
                                      commonmark={true}
                                    />
                                  ) : (
                                    t('No description of this targeting')
                                  )
                            }
                          />
                          <ItemMarkings
                            variant="inList"
                            markingDefinitions={stixCoreRelationship.objectMarking ?? []}
                            limit={1}
                          />
                          <ItemYears
                            variant="inList"
                            years={stixCoreRelationship.years}
                            country
                          />
                        </ListItemButton>
                      </ListItem>
                    );
                  })}
                  {orderedCountries.map((country) => {
                    const orderedSubRelations = R.pipe(
                      R.values,
                      R.sortWith([R.descend(R.prop('years'))]),
                    )(country.relations);
                    const orderedCities = R.pipe(
                      R.values,
                      R.sortWith([R.ascend(R.prop('name'))]),
                    )(country.cities);
                    return (
                      <div key={country.id}>
                        <ListItem
                          divider={true}
                          disablePadding
                          secondaryAction={(
                            <IconButton
                              onClick={this.handleToggleLine.bind(
                                this,
                                country.id,
                              )}
                              aria-haspopup="true"
                            >
                              {this.state.expandedLines[country.id] === true ? (
                                <ExpandLess />
                              ) : (
                                <ExpandMore />
                              )}
                            </IconButton>
                          )}
                        >
                          <ListItemButton
                            classes={{ root: classes.nested }}
                            onClick={this.handleToggleLine.bind(this, country.id)}
                          >
                            <ListItemIcon>
                              <Flag role="img" />
                            </ListItemIcon>
                            <ListItemText primary={country.name} />

                          </ListItemButton>
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
                                  divider={true}
                                  dense={true}
                                  disablePadding
                                  secondaryAction={stixCoreRelationship.is_inferred ? (
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
                                >
                                  <ListItemButton
                                    classes={{ root: classes.subnested }}
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

                                        stixCoreRelationship.description
                                        && stixCoreRelationship.description.length
                                        > 0 ? (
                                              <MarkdownDisplay
                                                content={
                                                  stixCoreRelationship.description
                                                }
                                                remarkGfmPlugin={true}
                                                commonmark={true}
                                              />
                                            ) : stixCoreRelationship.inferred ? (
                                              <i>{t('This relation is inferred')}</i>
                                            ) : (
                                              t('No description of this targeting')
                                            )
                                      }
                                    />
                                    <ItemMarkings
                                      variant="inList"
                                      markingDefinitions={stixCoreRelationship.objectMarking ?? []}
                                      limit={1}
                                    />
                                    <ItemYears
                                      variant="inList"
                                      years={stixCoreRelationship.years}
                                    />
                                  </ListItemButton>
                                </ListItem>
                              );
                            })}
                            {orderedCities.map((city) => {
                              const orderedSubSubRelations = R.pipe(
                                R.values,
                                R.sortWith([R.descend(R.prop('years'))]),
                              )(city.relations);
                              return (
                                <div key={city.id}>
                                  {orderedSubSubRelations.map(
                                    (stixCoreRelationship) => {
                                      const link = `${entityLink}/relations/${stixCoreRelationship.id}`;
                                      return (
                                        <ListItem
                                          key={stixCoreRelationship.id}
                                          divider={true}
                                          dense={true}
                                          disablePadding
                                          secondaryAction={stixCoreRelationship.is_inferred ? (
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
                                        >
                                          <ListItemButton
                                            classes={{
                                              root: classes.subnested,
                                            }}
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

                                                stixCoreRelationship.description
                                                && stixCoreRelationship.description
                                                  .length > 0 ? (
                                                      <MarkdownDisplay
                                                        content={
                                                          stixCoreRelationship.description
                                                        }
                                                        remarkGfmPlugin={true}
                                                        commonmark={true}
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
                                            <ItemMarkings
                                              variant="inList"
                                              markingDefinitions={stixCoreRelationship.objectMarking ?? []}
                                              limit={1}
                                            />
                                            <ItemYears
                                              variant="inList"
                                              years={stixCoreRelationship.years}
                                            />
                                          </ListItemButton>
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

export default R.compose(
  inject18n,
  withStyles(styles),
)(StixDomainObjectVictimologyRegionsList);
