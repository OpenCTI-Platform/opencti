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
import { Domain, ExpandLess, ExpandMore, FileDownloadOutlined, LibraryBooksOutlined } from '@mui/icons-material';
import { AutoFix, FormatListGroup, RelationManyToMany } from 'mdi-material-ui';
import { createRefetchContainer, graphql } from 'react-relay';
import Tooltip from '@mui/material/Tooltip';
import ToggleButtonGroup from '@mui/material/ToggleButtonGroup';
import ToggleButton from '@mui/material/ToggleButton';
import { ListItemButton } from '@mui/material';
import ListItem from '@mui/material/ListItem';
import { yearFormat } from '../../../../utils/Time';
import inject18n from '../../../../components/i18n';
import StixCoreRelationshipPopover from '../stix_core_relationships/StixCoreRelationshipPopover';
import StixCoreRelationshipCreationFromEntity from '../stix_core_relationships/StixCoreRelationshipCreationFromEntity';
import ItemYears from '../../../../components/ItemYears';
import SearchInput from '../../../../components/SearchInput';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNGETEXPORT, KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';
import ItemIcon from '../../../../components/ItemIcon';
import { buildViewParamsFromUrlAndStorage, saveViewParameters } from '../../../../utils/ListParameters';
import StixCoreRelationshipsExports from '../stix_core_relationships/StixCoreRelationshipsExports';
import ItemMarkings from '../../../../components/ItemMarkings';
import { export_max_size } from '../../../../utils/utils';
import MarkdownDisplay from '../../../../components/MarkdownDisplay';
import withRouter from '../../../../utils/compat_router/withRouter';

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
  parameters: {
    marginBottom: 10,
  },
});

class StixDomainObjectVictimologySectorsComponent extends Component {
  constructor(props) {
    const LOCAL_STORAGE_KEY = `victimology-sectors-${props.entityId}`;
    super(props);
    let params = {};
    if (!props.noState) {
      params = buildViewParamsFromUrlAndStorage(
        props.navigate,
        props.location,
        LOCAL_STORAGE_KEY,
      );
    }
    this.state = {
      sortBy: R.propOr('created_at', 'sortBy', params),
      orderAsc: R.propOr(false, 'orderAsc', params),
      searchTerm: R.propOr('', 'searchTerm', params),
      view: R.propOr('lines', 'view', params),
      openEntityType: false,
      openRelationshipType: false,
      openExports: false,
      expandedLines: {},
    };
  }

  saveView() {
    if (!this.props.noState) {
      const LOCAL_STORAGE_KEY = `victimology-sectors-${this.props.entityId}`;
      saveViewParameters(
        this.props.navigate,
        this.props.location,
        LOCAL_STORAGE_KEY,
        this.state,
      );
    }
  }

  handleSort(field, orderAsc) {
    this.setState({ sortBy: field, orderAsc }, () => this.saveView());
  }

  handleSearch(value) {
    this.setState({ searchTerm: value }, () => this.saveView());
  }

  handleToggleExports() {
    this.setState({ openExports: !this.state.openExports });
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
    const { searchTerm, openExports } = this.state;
    const {
      t,
      classes,
      data,
      entityLink,
      paginationOptions,
      stixDomainObjectId,
      handleChangeView,
      defaultStartTime,
      defaultStopTime,
    } = this.props;
    const filterByKeyword = (n) => searchTerm === ''
      || n.name.toLowerCase().indexOf(searchTerm.toLowerCase()) !== -1
      || n.description.toLowerCase().indexOf(searchTerm.toLowerCase()) !== -1
      || R.propOr('', 'subsectors_text', n)
        .toLowerCase()
        .indexOf(searchTerm.toLowerCase()) !== -1;
    const unknownSectorId = 'a8c03ed6-cc9e-444d-9146-66c64220fff9';
    const concatAll = R.reduce(R.concat, []);
    // Extract all sectors
    const sectors = R.pipe(
      R.filter(
        (n) => n.node.to.entity_type === 'Sector' && !n.node.to.isSubSector,
      ),
      R.map((n) => ({
        id: n.node.to.id,
        name: n.node.to.name,
        description: n.node.to.description,
        subSectors: {},
        subsectors_text: '',
        relations: [],
      })),
    )(data.stixCoreRelationships.edges);
    const subSectors = R.pipe(
      R.filter(
        (n) => n.node.to.entity_type === 'Sector' && n.node.to.isSubSector,
      ),
      R.map((n) => ({
        id: n.node.to.id,
        name: n.node.to.name,
        parentSectors: R.map(
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
      R.pluck('parentSectors', subSectors),
    );
    const organizations = R.pipe(
      R.filter((n) => n.node.to.entity_type === 'Organization'),
      R.map((n) => ({
        id: n.node.to.id,
        name: n.node.to.name,
        sectors: R.map(
          (o) => ({
            id: o.node.id,
            name: o.node.name,
            isSubSector: o.node.isSubSector,
            subSectors: {},
            parentSectors: R.map(
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
    const organizationsSectors = concatAll(R.pluck('sectors', organizations));
    const organizationsTopLevelSectors = R.filter(
      (n) => !n.isSubSector,
      organizationsSectors,
    );
    const organizationsParentSectors = concatAll(
      R.pluck('parentSectors', organizationsSectors),
    );
    const finalSectors = R.pipe(
      R.concat(subSectorsParentSectors),
      R.concat(organizationsTopLevelSectors),
      R.concat(organizationsParentSectors),
      R.uniq,
      R.indexBy(R.prop('id')),
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
      if (stixCoreRelationship.to.entity_type === 'Sector') {
        if (stixCoreRelationship.to.isSubSector) {
          const parentSectorId = R.head(
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
          const sector = R.head(stixCoreRelationship.to.sectors.edges).node;
          if (sector.isSubSector) {
            const parentSectorId = R.head(sector.parentSectors.edges).node.id;
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
    const orderedFinalSectors = R.pipe(
      R.values,
      R.sortWith([R.ascend(R.prop('name'))]),
      R.filter(filterByKeyword),
    )(finalSectors);
    const exportDisabled = orderedFinalSectors.length > export_max_size;
    return (
      <div>
        <div className={classes.parameters}>
          <div style={{ float: 'left', marginRight: 20 }}>
            <SearchInput
              variant="small"
              onSubmit={this.handleSearch.bind(this)}
              keyword={searchTerm}
            />
          </div>
          <div className={classes.views}>
            <div style={{ float: 'right', marginTop: -10 }}>
              <ToggleButtonGroup
                size="small"
                color="secondary"
                value="nested"
                exclusive={true}
                onChange={(_, value) => {
                  if (value && value === 'export') {
                    this.handleToggleExports();
                  } else if (value) {
                    handleChangeView(value);
                  }
                }}
                style={{ margin: '8px 0 0 5px' }}
              >
                <ToggleButton value="entities" aria-label="entities">
                  <Tooltip title={t('Entities view')}>
                    <LibraryBooksOutlined
                      fontSize="small"
                      color="primary"
                    />
                  </Tooltip>
                </ToggleButton>
                <ToggleButton value="relationships" aria-label="lines">
                  <Tooltip title={t('Relationships view')}>
                    <RelationManyToMany fontSize="small" color="primary" />
                  </Tooltip>
                </ToggleButton>
                <ToggleButton value="nested" aria-label="nested">
                  <Tooltip title={t('Nested view')}>
                    <FormatListGroup fontSize="small" />
                  </Tooltip>
                </ToggleButton>
                {!exportDisabled && (
                  <ToggleButton value="export" aria-label="export">
                    <Tooltip title={t('Open export panel')}>
                      <FileDownloadOutlined
                        fontSize="small"
                        color={openExports ? 'secondary' : 'primary'}
                      />
                    </Tooltip>
                  </ToggleButton>
                )}
                {exportDisabled && (
                  <Tooltip
                    title={`${
                      t(
                        'Export is disabled because too many entities are targeted (maximum number of entities is: ',
                      ) + export_max_size
                    })`}
                  >
                    <span>
                      <ToggleButton
                        size="small"
                        value="export"
                        aria-label="export"
                        disabled={true}
                      >
                        <FileDownloadOutlined fontSize="small" />
                      </ToggleButton>
                    </span>
                  </Tooltip>
                )}
              </ToggleButtonGroup>
            </div>
          </div>
          <div className="clearfix" />
        </div>
        <List>
          {orderedFinalSectors.map((sector) => {
            const orderedRelations = R.pipe(
              R.values,
              R.sortWith([R.descend(R.prop('years'))]),
            )(sector.relations);
            const orderedSubSectors = R.pipe(
              R.values,
              R.sortWith([R.ascend(R.prop('name'))]),
            )(sector.subSectors);
            return (
              <div key={sector.id}>
                <ListItem
                  divider={true}
                  disablePadding
                  secondaryAction={(
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
                  )}
                >
                  <ListItemButton onClick={this.handleToggleLine.bind(this, sector.id)}>
                    <ListItemIcon>
                      <Domain role="img" />
                    </ListItemIcon>
                    <ListItemText primary={sector.name} />
                  </ListItemButton>
                </ListItem>
                <Collapse in={this.state.expandedLines[sector.id] === true}>
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
                              onDelete={this.props.relay.refetch.bind(this)}
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
                                stixCoreRelationship.to.id === sector.id ? (
                                  <em>{t('Direct targeting of this sector')}</em>
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
                            />
                          </ListItemButton>
                        </ListItem>
                      );
                    })}
                    {orderedSubSectors.map((subsector) => {
                      const orderedSubRelations = R.pipe(
                        R.values,
                        R.sortWith([R.descend(R.prop('years'))]),
                      )(subsector.relations);
                      return (
                        <div key={subsector.id}>
                          <ListItem
                            divider={true}
                            disablePadding
                            secondaryAction={(
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
                            )}
                          >
                            <ListItemButton
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
                            </ListItemButton>
                          </ListItem>
                          <Collapse
                            in={this.state.expandedLines[subsector.id] === true}
                          >
                            <List>
                              {orderedSubRelations.map(
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
                                          onDelete={this.props.relay.refetch.bind(
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
                                        <ListItemIcon
                                          className={classes.itemIcon}
                                        >
                                          <ItemIcon
                                            type={
                                              stixCoreRelationship.to.entity_type
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

                                            stixCoreRelationship.description
                                            && stixCoreRelationship.description
                                              .length > 0 ? (
                                                  <MarkdownDisplay
                                                    content={
                                                      stixCoreRelationship.description
                                                    }
                                                    remarkGfmPlugin={true}
                                                    commonmark={true}
                                                  >
                                                  </MarkdownDisplay>
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
        <Security needs={[KNOWLEDGE_KNGETEXPORT]}>
          <StixCoreRelationshipsExports
            open={openExports}
            handleToggle={this.handleToggleExports.bind(this)}
            paginationOptions={paginationOptions}
            exportContext={{ entity_type: 'stix-core-relationship' }}
          />
        </Security>
        <Security needs={[KNOWLEDGE_KNUPDATE]}>
          <StixCoreRelationshipCreationFromEntity
            entityId={stixDomainObjectId}
            isRelationReversed={false}
            paddingRight={220}
            onCreate={this.props.relay.refetch.bind(this)}
            targetStixDomainObjectTypes={['Sector', 'Organization']}
            allowedRelationshipTypes={['targets']}
            paginationOptions={paginationOptions}
            defaultStartTime={defaultStartTime}
            defaultStopTime={defaultStopTime}
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
  handleChangeView: PropTypes.func,
  classes: PropTypes.object,
  t: PropTypes.func,
  defaultStartTime: PropTypes.string,
  defaultStopTime: PropTypes.string,
};

export const stixDomainObjectVictimologySectorsStixCoreRelationshipsQuery = graphql`
  query StixDomainObjectVictimologySectorsStixCoreRelationshipsQuery(
    $fromId: [String]
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
                ... on Event {
                  name
                  description
                  start_time
                  stop_time
                }
              }
              objectMarking {
                id
                definition_type
                definition
                x_opencti_order
                x_opencti_color
              }
            }
          }
        }
      }
    `,
  },
  stixDomainObjectVictimologySectorsStixCoreRelationshipsQuery,
);

export default R.compose(
  inject18n,
  withRouter,
  withStyles(styles),
)(StixDomainObjectVictimologySectorsSectorLines);
