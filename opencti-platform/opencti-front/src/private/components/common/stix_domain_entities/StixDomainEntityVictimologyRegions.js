import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Link } from 'react-router-dom';
import html2canvas from 'html2canvas';
import fileDownload from 'js-file-download';
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
import { FileImageOutline } from 'mdi-material-ui';
import {
  ExpandLess, ExpandMore, Map, Flag,
} from '@material-ui/icons';
import { createRefetchContainer } from 'react-relay';
import Tooltip from '@material-ui/core/Tooltip';
import { yearFormat } from '../../../../utils/Time';
import inject18n from '../../../../components/i18n';
import StixRelationPopover from '../stix_relations/StixRelationPopover';
import StixRelationCreationFromEntity from '../stix_relations/StixRelationCreationFromEntity';
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

class StixDomainEntityVictimologyRegionsComponent extends Component {
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

  setInlineStyles(targetElem) {
    const transformProperties = [
      'fill',
      'color',
      'font-size',
      'stroke',
      'font',
    ];
    const svgElems = Array.from(targetElem.getElementsByTagName('svg'));
    function recurseElementChildren(node) {
      if (!node.style) return;
      const inlineStyles = getComputedStyle(node);
      for (const transformProperty of transformProperties) {
        node.style[transformProperty] = inlineStyles[transformProperty];
      }
      for (const child of Array.from(node.childNodes)) {
        recurseElementChildren(child);
      }
    }
    for (const svgElement of svgElems) {
      if (svgElement.getAttribute('role') === 'img') {
        recurseElementChildren(svgElement);
        svgElement.setAttribute(
          'width',
          svgElement.getBoundingClientRect().width,
        );
        svgElement.setAttribute(
          'height',
          svgElement.getBoundingClientRect().height,
        );
      }
    }
  }

  exportImage() {
    const container = document.getElementById('container');
    this.setInlineStyles(container);
    html2canvas(container, {
      useCORS: true,
      allowTaint: true,
      backgroundColor: '#303030',
    }).then((canvas) => {
      canvas.toBlob((blob) => {
        fileDownload(blob, 'Victimology.png', 'image/png');
      });
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

    const unknownRegionId = 'fe15f901-07eb-4b28-b5a4-54f6d589a337';
    const unknownCountryId = '5b1e93ff-9b3d-4ab5-b1bd-3fd95dc17626';

    // Extract all regions
    const regions = pipe(
      filter((n) => n.node.to.entity_type === 'region'),
      map((n) => ({
        id: n.node.to.id,
        name: n.node.to.name,
        countries: {},
        relations: [],
      })),
    )(data.stixRelations.edges);
    const countries = pipe(
      filter((n) => n.node.to.entity_type === 'country'),
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
    )(data.stixRelations.edges);
    const countriesRegions = filter(
      (n) => n !== null,
      pluck('region', countries),
    );
    const cities = pipe(
      filter((n) => n.node.to.entity_type === 'city'),
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
    )(data.stixRelations.edges);
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
    for (const stixRelationEdge of data.stixRelations.edges) {
      let stixRelation = stixRelationEdge.node;
      stixRelation = assoc(
        'firstSeenYear',
        yearFormat(stixRelation.first_seen),
        stixRelation,
      );
      stixRelation = assoc(
        'lastSeenYear',
        yearFormat(stixRelation.last_seen),
        stixRelation,
      );
      stixRelation = assoc(
        'years',
        stixRelation.firstSeenYear === stixRelation.lastSeenYear
          ? stixRelation.firstSeenYear
          : `${stixRelation.firstSeenYear} - ${stixRelation.lastSeenYear}`,
        stixRelation,
      );
      if (stixRelation.to.entity_type === 'region') {
        finalRegions[stixRelation.to.id].relations.push(stixRelation);
      }
      if (stixRelation.to.entity_type === 'country') {
        if (stixRelation.to.region) {
          finalRegions[stixRelation.to.region.id].countries[
            stixRelation.to.id
          ].relations.push(stixRelation);
        } else {
          if (!(unknownRegionId in finalRegions)) {
            finalRegions[unknownRegionId] = {
              id: unknownRegionId,
              name: 'Unknown',
              countries: {},
              relations: [],
            };
          }
          finalRegions[unknownRegionId].relations.push(stixRelation);
        }
      }
      if (stixRelation.to.entity_type === 'city') {
        if (stixRelation.to.country) {
          if (stixRelation.to.country.region) {
            finalRegions[stixRelation.to.country.region.id].countries[
              stixRelation.to.country.id
            ].cities[stixRelation.to.id].relations.push(stixRelation);
          } else {
            if (!(unknownRegionId in finalRegions)) {
              finalRegions[unknownRegionId] = {
                id: unknownRegionId,
                name: 'Unknown',
                countries: {},
                relations: [],
              };
            }
            if (
              !(stixRelation.to.country.id in finalRegions[unknownRegionId])
            ) {
              finalRegions[unknownRegionId].countries[
                stixRelation.to.country.id
              ] = {
                id: stixRelation.to.country.id,
                name: stixRelation.to.country.name,
                cities: {},
                relations: [],
              };
            }
            finalRegions[unknownRegionId].countries[
              stixRelation.country.id
            ].relations.push(stixRelation);
          }
        } else {
          if (!(unknownRegionId in finalRegions)) {
            finalRegions[unknownRegionId] = {
              id: unknownRegionId,
              name: 'Unknown',
              countries: {},
              relations: [],
            };
          }
          if (!(unknownCountryId in finalRegions[unknownRegionId].countries)) {
            finalRegions[unknownRegionId].countries[unknownCountryId] = {
              id: unknownCountryId,
              name: 'Unknown',
              cities: {},
              relations: [],
            };
          }
          finalRegions[unknownRegionId].countries[
            unknownCountryId
          ].relations.push(stixRelation);
        }
      }
    }

    const orderedFinalRegions = pipe(
      values,
      sortWith([ascend(prop('name'))]),
    )(finalRegions);
    return (
      <div>
        <div style={{ float: 'left' }}>
          <SearchInput
            variant="small"
            onSubmit={this.handleSearch.bind(this)}
          />
        </div>
        <div style={{ float: 'right', paddingRight: 18 }}>
          <Tooltip title={t('Export as image')}>
            <IconButton color="primary" onClick={this.exportImage.bind(this)}>
              <FileImageOutline />
            </IconButton>
          </Tooltip>
        </div>
        <div className="clearfix" />
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
                      {orderedRelations.map((stixRelation) => {
                        const link = `${entityLink}/relations/${stixRelation.id}`;
                        return (
                          <ListItem
                            key={stixRelation.id}
                            classes={{ root: classes.nested }}
                            divider={true}
                            button={true}
                            dense={true}
                            component={Link}
                            to={link}
                          >
                            <ListItemIcon className={classes.itemIcon}>
                              <ItemIcon type={stixRelation.to.entity_type} />
                            </ListItemIcon>
                            <ListItemText
                              primary={
                                stixRelation.to.id === region.id ? (
                                  <em>
                                    {t('Direct targeting of this region')}
                                  </em>
                                ) : (
                                  stixRelation.to.name
                                )
                              }
                              secondary={
                                // eslint-disable-next-line no-nested-ternary
                                stixRelation.description
                                && stixRelation.description.length > 0 ? (
                                  <Markdown
                                    className="markdown"
                                    source={stixRelation.description}
                                  />
                                  ) : stixRelation.inferred ? (
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
                                stixRelation,
                              ),
                            ).map((markingDefinition) => (
                              <ItemMarking
                                key={markingDefinition.node.id}
                                variant="inList"
                                label={markingDefinition.node.definition}
                                color={markingDefinition.node.color}
                              />
                            ))}
                            <ItemYears
                              variant="inList"
                              years={
                                stixRelation.inferred
                                  ? t('Inferred')
                                  : stixRelation.years
                              }country
                              disabled={stixRelation.inferred}
                            />
                            <ListItemSecondaryAction>
                              <StixRelationPopover
                                stixRelationId={stixRelation.id}
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
                                {orderedSubRelations.map((stixRelation) => {
                                  const link = `${entityLink}/relations/${stixRelation.id}`;
                                  return (
                                    <ListItem
                                      key={stixRelation.id}
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
                                          type={stixRelation.to.entity_type}
                                        />
                                      </ListItemIcon>
                                      <ListItemText
                                        primary={
                                          stixRelation.to.id === country.id ? (
                                            <em>
                                              {t(
                                                'Direct targeting of this country',
                                              )}
                                            </em>
                                          ) : (
                                            stixRelation.to.name
                                          )
                                        }
                                        secondary={
                                          // eslint-disable-next-line no-nested-ternary
                                          stixRelation.description
                                          && stixRelation.description.length
                                            > 0 ? (
                                            <Markdown
                                              className="markdown"
                                              source={stixRelation.description}
                                            />
                                            ) : stixRelation.inferred ? (
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
                                          stixRelation,
                                        ),
                                      ).map((markingDefinition) => (
                                        <ItemMarking
                                          key={markingDefinition.node.id}
                                          variant="inList"
                                          label={
                                            markingDefinition.node.definition
                                          }
                                          color={markingDefinition.node.color}
                                        />
                                      ))}
                                      <ItemYears
                                        variant="inList"
                                        years={
                                          stixRelation.inferred
                                            ? t('Inferred')
                                            : stixRelation.years
                                        }
                                        disabled={stixRelation.inferred}
                                      />
                                      <ListItemSecondaryAction>
                                        <StixRelationPopover
                                          stixRelationId={stixRelation.id}
                                          paginationOptions={paginationOptions}
                                          onDelete={this.props.relay.refetch.bind(
                                            this,
                                          )}
                                        />
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
                                        (stixRelation) => {
                                          const link = `${entityLink}/relations/${stixRelation.id}`;
                                          return (
                                            <ListItem
                                              key={stixRelation.id}
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
                                                    stixRelation.to.entity_type
                                                  }
                                                />
                                              </ListItemIcon>
                                              <ListItemText
                                                primary={
                                                  stixRelation.to.id
                                                  === country.id ? (
                                                    <em>
                                                      {t(
                                                        'Direct targeting of this country',
                                                      )}
                                                    </em>
                                                    ) : (
                                                      stixRelation.to.name
                                                    )
                                                }
                                                secondary={
                                                  // eslint-disable-next-line no-nested-ternary
                                                  stixRelation.description
                                                  && stixRelation.description
                                                    .length > 0 ? (
                                                    <Markdown
                                                      className="markdown"
                                                      source={
                                                        stixRelation.description
                                                      }
                                                    />
                                                    ) : stixRelation.inferred ? (
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
                                                  stixRelation,
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
                                                    markingDefinition.node.color
                                                  }
                                                />
                                              ))}
                                              <ItemYears
                                                variant="inList"
                                                years={
                                                  stixRelation.inferred
                                                    ? t('Inferred')
                                                    : stixRelation.years
                                                }
                                                disabled={stixRelation.inferred}
                                              />
                                              <ListItemSecondaryAction>
                                                <StixRelationPopover
                                                  stixRelationId={
                                                    stixRelation.id
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
          <StixRelationCreationFromEntity
            entityId={stixDomainEntityId}
            isFrom={true}
            paddingRight={true}
            onCreate={this.props.relay.refetch.bind(this)}
            targetEntityTypes={['Identity']}
            paginationOptions={paginationOptions}
          />
        </Security>
      </div>
    );
  }
}

StixDomainEntityVictimologyRegionsComponent.propTypes = {
  stixDomainEntityId: PropTypes.string,
  data: PropTypes.object,
  entityLink: PropTypes.string,
  paginationOptions: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

export const stixDomainEntityVictimologyRegionsStixRelationsQuery = graphql`
  query StixDomainEntityVictimologyRegionsStixRelationsQuery(
    $fromId: String
    $toTypes: [String]
    $relationType: String
    $inferred: Boolean
    $first: Int
  ) {
    ...StixDomainEntityVictimologyRegions_data
  }
`;

const StixDomainEntityVictimologyRegionsSectorLines = createRefetchContainer(
  StixDomainEntityVictimologyRegionsComponent,
  {
    data: graphql`
      fragment StixDomainEntityVictimologyRegions_data on Query {
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
              inferred
              to {
                id
                name
                entity_type
                ... on City {
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
                  region {
                    id
                    name
                  }
                }
                ... on Region {
                  id
                  name
                }
              }
              markingDefinitions {
                edges {
                  node {
                    id
                    definition
                    color
                  }
                }
              }
            }
          }
        }
      }
    `,
  },
  stixDomainEntityVictimologyRegionsStixRelationsQuery,
);

export default compose(
  inject18n,
  withStyles(styles),
)(StixDomainEntityVictimologyRegionsSectorLines);
