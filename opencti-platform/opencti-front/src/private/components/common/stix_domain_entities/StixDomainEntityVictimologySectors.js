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
import { FileImageOutline } from 'mdi-material-ui';
import { Domain, ExpandLess, ExpandMore } from '@material-ui/icons';
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

class StixDomainEntityVictimologySectorsComponent extends Component {
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

    const unknownSectorId = 'a8c03ed6-cc9e-444d-9146-66c64220fff9';
    const concatAll = reduce(concat, []);

    // Extract all sectors
    const sectors = pipe(
      filter((n) => n.node.to.entity_type === 'sector' && !n.node.to.isSubSector),
      map((n) => ({
        id: n.node.to.id,
        name: n.node.to.name,
        subSectors: {},
        relations: [],
      })),
    )(data.stixRelations.edges);
    const subSectors = pipe(
      filter((n) => n.node.to.entity_type === 'sector' && n.node.to.isSubSector),
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
    )(data.stixRelations.edges);
    const subSectorsParentSectors = concatAll(
      pluck('parentSectors', subSectors),
    );
    const organizations = pipe(
      filter((n) => n.node.to.entity_type === 'organization'),
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
    )(data.stixRelations.edges);
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
      if (stixRelation.to.entity_type === 'sector') {
        if (stixRelation.to.isSubSector) {
          const parentSectorId = head(stixRelation.to.parentSectors.edges).node
            .id;
          finalSectors[parentSectorId].subSectors[
            stixRelation.to.id
          ].relations.push(stixRelation);
        } else {
          finalSectors[stixRelation.to.id].relations.push(stixRelation);
        }
      }
      if (stixRelation.to.entity_type === 'organization') {
        if (stixRelation.to.sectors.edges.length > 0) {
          const sector = head(stixRelation.to.sectors.edges).node;
          if (sector.isSubSector) {
            const parentSectorId = head(sector.parentSectors.edges).node.id;
            finalSectors[parentSectorId].subSectors[sector.id].relations.push(
              stixRelation,
            );
          } else {
            finalSectors[sector.id].relations.push(stixRelation);
          }
        } else {
          if (!(unknownSectorId in finalSectors)) {
            finalSectors[unknownSectorId] = {
              id: unknownSectorId,
              name: 'Unknown',
              relations: [],
            };
          }
          finalSectors[unknownSectorId].relations.push(stixRelation);
        }
      }
    }
    const orderedFinalSectors = pipe(
      values,
      sortWith([ascend(prop('name'))]),
    )(finalSectors);
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
                                stixRelation.to.id === sector.id ? (
                                  <em>
                                    {t('Direct targeting of this sector')}
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
                              }
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
                                          stixRelation.to.id
                                          === subsector.id ? (
                                            <em>
                                              {t(
                                                'Direct targeting of this sector',
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

StixDomainEntityVictimologySectorsComponent.propTypes = {
  stixDomainEntityId: PropTypes.string,
  data: PropTypes.object,
  entityLink: PropTypes.string,
  paginationOptions: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

export const stixDomainEntityVictimologySectorsStixRelationsQuery = graphql`
  query StixDomainEntityVictimologySectorsStixRelationsQuery(
    $fromId: String
    $toTypes: [String]
    $relationType: String
    $inferred: Boolean
    $first: Int
  ) {
    ...StixDomainEntityVictimologySectors_data
  }
`;

const StixDomainEntityVictimologySectorsSectorLines = createRefetchContainer(
  StixDomainEntityVictimologySectorsComponent,
  {
    data: graphql`
      fragment StixDomainEntityVictimologySectors_data on Query {
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
                ... on Organization {
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
  stixDomainEntityVictimologySectorsStixRelationsQuery,
);

export default compose(
  inject18n,
  withStyles(styles),
)(StixDomainEntityVictimologySectorsSectorLines);
