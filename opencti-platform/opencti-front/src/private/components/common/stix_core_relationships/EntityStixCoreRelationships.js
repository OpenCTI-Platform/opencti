import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose, includes, pipe, assoc, propOr } from 'ramda';
import withStyles from '@mui/styles/withStyles';
import Drawer from '@mui/material/Drawer';
import Grid from '@mui/material/Grid';
import Select from '@mui/material/Select';
import MenuItem from '@mui/material/MenuItem';
import { QueryRenderer } from '../../../../relay/environment';
import ListLines from '../../../../components/list_lines/ListLines';
import inject18n from '../../../../components/i18n';
import StixCoreRelationshipCreationFromEntity from './StixCoreRelationshipCreationFromEntity';
import Security, { KNOWLEDGE_KNUPDATE } from '../../../../utils/Security';
import EntityStixCoreRelationshipsLinesFrom, {
  entityStixCoreRelationshipsLinesFromQuery,
} from './EntityStixCoreRelationshipsLinesFrom';
import EntityStixCoreRelationshipsLinesTo, {
  entityStixCoreRelationshipsLinesToQuery,
} from './EntityStixCoreRelationshipsLinesTo';
import {
  buildViewParamsFromUrlAndStorage,
  saveViewParameters,
} from '../../../../utils/ListParameters';
import EntityStixCoreRelationshipsLinesAll, {
  entityStixCoreRelationshipsLinesAllQuery,
} from './EntityStixCoreRelationshipsLinesAll';

const styles = (theme) => ({
  bottomNav: {
    zIndex: 1000,
    padding: '10px 200px 10px 205px',
    display: 'flex',
  },
  container: {
    marginTop: 15,
    paddingBottom: 70,
  },
  chips: {
    display: 'flex',
    flexWrap: 'wrap',
  },
  chip: {
    margin: theme.spacing(1) / 4,
  },
});

class EntityStixCoreRelationships extends Component {
  constructor(props) {
    super(props);
    let params = {};
    if (!props.noState) {
      params = buildViewParamsFromUrlAndStorage(
        props.history,
        props.location,
        `view-relationships-${props.entityId}`,
      );
    }
    this.state = {
      sortBy: propOr(null, 'sortBy', params),
      orderAsc: propOr(false, 'orderAsc', params),
      searchTerm: propOr('', 'searchTerm', params),
      view: propOr('lines', 'view', params),
      selectedEntityType: propOr('All', 'selectedEntityType', params),
      selectedRelationshipType:
        props.relationshipTypes
        && ['All', ...props.relationshipTypes].includes(
          propOr('All', 'selectedRelationshipType', params),
        )
          ? propOr('All', 'selectedRelationshipType', params)
          : 'All',
      numberOfElements: { number: 0, symbol: '' },
      openEntityType: false,
      openRelationshipType: false,
    };
  }

  saveView() {
    if (!this.props.noState) {
      saveViewParameters(
        this.props.history,
        this.props.location,
        `view-relationships-${this.props.entityId}`,
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

  handleOpenEntityType() {
    this.setState({ openEntityType: true });
  }

  handleCloseEntityType() {
    this.setState({ openEntityType: false });
  }

  handleOpenRelationshipType() {
    this.setState({ openRelationshipType: true });
  }

  handleCloseRelationshipType() {
    this.setState({ openRelationshipType: false });
  }

  handleChangeEntities(event) {
    const { value } = event.target;
    return this.setState(
      { openEntityType: false, selectedEntityType: value },
      () => this.saveView(),
    );
  }

  handleChangeRelationshipType(event) {
    const { value } = event.target;
    return this.setState(
      {
        openRelationshipType: false,
        selectedRelationshipType: value,
      },
      () => this.saveView(),
    );
  }

  setNumberOfElements(numberOfElements) {
    this.setState({ numberOfElements });
  }

  renderBottomMenu() {
    const { t, classes, targetStixDomainObjectTypes, relationshipTypes } = this.props;
    const {
      openEntityType,
      openRelationshipType,
      selectedEntityType,
      selectedRelationshipType,
    } = this.state;
    const displayTypes = targetStixDomainObjectTypes.length > 1
      || targetStixDomainObjectTypes.includes('Identity')
      || targetStixDomainObjectTypes.includes('Location');
    const displayRelationshipTypes = relationshipTypes.length > 1;
    return (
      <Drawer
        anchor="bottom"
        variant="permanent"
        classes={{ paper: classes.bottomNav }}
        elevation={3}
      >
        <Grid container={true} spacing={1}>
          {displayTypes && (
            <Grid item={true} xs="auto">
              <Select
                size="small"
                value={selectedEntityType}
                open={openEntityType}
                onClose={this.handleCloseEntityType.bind(this)}
                onOpen={this.handleOpenEntityType.bind(this)}
                onChange={this.handleChangeEntities.bind(this)}
              >
                <MenuItem value="All">{t('All entities')}</MenuItem>
                {includes('Attack-Pattern', targetStixDomainObjectTypes) && (
                  <MenuItem value="Attack-Pattern">
                    {t('Attack pattern')}
                  </MenuItem>
                )}
                {includes('Campaign', targetStixDomainObjectTypes) && (
                  <MenuItem value="Campaign">{t('Campaign')}</MenuItem>
                )}
                {includes('Note', targetStixDomainObjectTypes) && (
                  <MenuItem value="Note">{t('Note')}</MenuItem>
                )}
                {includes('Observed-Data', targetStixDomainObjectTypes) && (
                  <MenuItem value="Observed-Data">
                    {t('Observed data')}
                  </MenuItem>
                )}
                {includes('Opinion', targetStixDomainObjectTypes) && (
                  <MenuItem value="Opinion">{t('Opinion')}</MenuItem>
                )}
                {includes('Report', targetStixDomainObjectTypes) && (
                  <MenuItem value="Report">{t('Report')}</MenuItem>
                )}
                {includes('Course-Of-Action', targetStixDomainObjectTypes) && (
                  <MenuItem value="Course-Of-Action">
                    {t('Course of action')}
                  </MenuItem>
                )}
                {targetStixDomainObjectTypes.some((r) => ['System', 'Identity'].includes(r)) && <MenuItem value="System">{t('System')}</MenuItem>}
                {targetStixDomainObjectTypes.some((r) => ['Individual', 'Identity'].includes(r)) && <MenuItem value="Individual">{t('Individual')}</MenuItem>}
                {targetStixDomainObjectTypes.some((r) => ['Organization', 'Identity'].includes(r)) && (
                  <MenuItem value="Organization">{t('Organization')}</MenuItem>
                )}
                {targetStixDomainObjectTypes.some((r) => ['Sector', 'Identity'].includes(r)) && <MenuItem value="Sector">{t('Sector')}</MenuItem>}
                {targetStixDomainObjectTypes.includes('Indicator') && (
                  <MenuItem value="Indicator">{t('Indicator')}</MenuItem>
                )}
                {targetStixDomainObjectTypes.includes('Infrastructure') && (
                  <MenuItem value="Infrastructure">
                    {t('Infrastructure')}
                  </MenuItem>
                )}
                {targetStixDomainObjectTypes.includes('Intrusion-Set') && (
                  <MenuItem value="Intrusion-Set">
                    {t('Intrusion set')}
                  </MenuItem>
                )}
                {targetStixDomainObjectTypes.some((r) => ['City', 'Location'].includes(r)) && <MenuItem value="City">{t('City')}</MenuItem>}
                {targetStixDomainObjectTypes.some((r) => ['Country', 'Location'].includes(r)) && <MenuItem value="Country">{t('Country')}</MenuItem>}
                {targetStixDomainObjectTypes.some((r) => ['Region', 'Location'].includes(r)) && <MenuItem value="Region">{t('Region')}</MenuItem>}
                {targetStixDomainObjectTypes.some((r) => ['Region', 'Position'].includes(r)) && <MenuItem value="Position">{t('Position')}</MenuItem>}
                {targetStixDomainObjectTypes.includes('Malware') && (
                  <MenuItem value="Malware">{t('Malware')}</MenuItem>
                )}
                {targetStixDomainObjectTypes.includes('Threat-Actor') && (
                  <MenuItem value="Threat-Actor">{t('Threat actor')}</MenuItem>
                )}
                {targetStixDomainObjectTypes.includes('Tool') && (
                  <MenuItem value="Tool">{t('Tool')}</MenuItem>
                )}
                {targetStixDomainObjectTypes.includes('Vulnerability') && (
                  <MenuItem value="Vulnerability">
                    {t('Vulnerability')}
                  </MenuItem>
                )}
                {targetStixDomainObjectTypes.includes('Incident') && (
                  <MenuItem value="Incident">{t('Incident')}</MenuItem>
                )}
              </Select>
            </Grid>
          )}
          {displayRelationshipTypes && (
            <Grid item={true} xs="auto">
              <Select
                size="small"
                value={selectedRelationshipType}
                open={openRelationshipType}
                onClose={this.handleCloseRelationshipType.bind(this)}
                onOpen={this.handleOpenRelationshipType.bind(this)}
                onChange={this.handleChangeRelationshipType.bind(this)}
              >
                <MenuItem value="All">
                  {t('All types of relationship')}
                </MenuItem>
                {relationshipTypes.map((relationshipType) => (
                  <MenuItem key={relationshipType} value={relationshipType}>
                    {t(`relationship_${relationshipType}`)}
                  </MenuItem>
                ))}
              </Select>
            </Grid>
          )}
        </Grid>
      </Drawer>
    );
  }

  renderLines(paginationOptions) {
    const { sortBy, orderAsc, numberOfElements } = this.state;
    const { entityLink, entityId, isRelationReversed, allDirections } = this.props;
    const dataColumns = {
      relationship_type: {
        label: 'Relationship type',
        width: '15%',
        isSortable: true,
      },
      name: {
        label: 'Name',
        width: '25%',
        isSortable: false,
      },
      entity_type: {
        label: 'Entity type',
        width: '20%',
        isSortable: false,
      },
      start_time: {
        label: 'Start time',
        width: '13%',
        isSortable: true,
      },
      stop_time: {
        label: 'Stop time',
        width: '13%',
        isSortable: true,
      },
      confidence: {
        label: 'Confidence',
        isSortable: true,
      },
    };
    return (
      <ListLines
        sortBy={sortBy}
        orderAsc={orderAsc}
        dataColumns={dataColumns}
        handleSort={this.handleSort.bind(this)}
        handleSearch={this.handleSearch.bind(this)}
        displayImport={true}
        secondaryAction={true}
        numberOfElements={numberOfElements}
      >
        <QueryRenderer
          query={
            // eslint-disable-next-line no-nested-ternary
            allDirections
              ? entityStixCoreRelationshipsLinesAllQuery
              : isRelationReversed
                ? entityStixCoreRelationshipsLinesToQuery
                : entityStixCoreRelationshipsLinesFromQuery
          }
          variables={{ count: 25, ...paginationOptions }}
          render={({ props }) =>
            /* eslint-disable-next-line no-nested-ternary,implicit-arrow-linebreak */
            (allDirections ? (
              <EntityStixCoreRelationshipsLinesAll
                data={props}
                paginationOptions={paginationOptions}
                entityLink={entityLink}
                entityId={entityId}
                dataColumns={dataColumns}
                initialLoading={props === null}
                setNumberOfElements={this.setNumberOfElements.bind(this)}
              />
            ) : isRelationReversed ? (
              <EntityStixCoreRelationshipsLinesTo
                data={props}
                paginationOptions={paginationOptions}
                entityLink={entityLink}
                dataColumns={dataColumns}
                initialLoading={props === null}
                setNumberOfElements={this.setNumberOfElements.bind(this)}
              />
            ) : (
              <EntityStixCoreRelationshipsLinesFrom
                data={props}
                paginationOptions={paginationOptions}
                entityLink={entityLink}
                dataColumns={dataColumns}
                initialLoading={props === null}
                setNumberOfElements={this.setNumberOfElements.bind(this)}
              />
            ))
          }
        />
      </ListLines>
    );
  }

  render() {
    const {
      classes,
      targetStixDomainObjectTypes,
      entityId,
      role,
      relationshipTypes,
      isRelationReversed,
      allDirections,
    } = this.props;
    const {
      view,
      searchTerm,
      selectedEntityType,
      selectedRelationshipType,
      sortBy,
      orderAsc,
    } = this.state;
    // Display types selection when target types are multiple
    const displayTypes = targetStixDomainObjectTypes.length > 1
      || targetStixDomainObjectTypes.includes('Identity')
      || targetStixDomainObjectTypes.includes('Location');
    const displayRelationshipTypes = relationshipTypes && relationshipTypes.length > 1;
    const displayBottomBar = displayTypes || displayRelationshipTypes;
    const selectedTypes = selectedEntityType === 'All'
      ? targetStixDomainObjectTypes
      : selectedEntityType;
    let relationshipType = 'stix-core-relationship';
    if (relationshipTypes && relationshipTypes.length === 1) {
      // eslint-disable-next-line prefer-destructuring
      relationshipType = relationshipTypes[0];
    } else if (selectedRelationshipType !== 'All') {
      relationshipType = selectedRelationshipType;
    }
    let paginationOptions = {
      relationship_type: relationshipType,
      search: searchTerm,
      orderBy: sortBy,
      orderMode: orderAsc ? 'asc' : 'desc',
    };
    if (
      relationshipTypes
      && relationshipTypes.length > 0
      && selectedRelationshipType === 'All'
    ) {
      paginationOptions = pipe(assoc('relationship_type', relationshipTypes))(
        paginationOptions,
      );
    }
    if (allDirections) {
      paginationOptions = pipe(
        assoc('elementId', entityId),
        assoc('elementWithTargetTypes', selectedTypes),
      )(paginationOptions);
    } else if (isRelationReversed) {
      paginationOptions = pipe(
        assoc('fromTypes', selectedTypes),
        assoc('toId', entityId),
        assoc('toRole', role || null),
      )(paginationOptions);
    } else {
      paginationOptions = pipe(
        assoc('fromId', entityId),
        assoc('fromRole', role || null),
        assoc('toTypes', selectedTypes),
      )(paginationOptions);
    }
    return (
      <div className={classes.container}>
        {displayBottomBar && this.renderBottomMenu()}
        {view === 'lines' && this.renderLines(paginationOptions)}
        <Security needs={[KNOWLEDGE_KNUPDATE]}>
          <StixCoreRelationshipCreationFromEntity
            entityId={entityId}
            isRelationReversed={isRelationReversed}
            paddingRight={220}
            targetStixDomainObjectTypes={targetStixDomainObjectTypes}
            allowedRelationshipTypes={relationshipTypes}
            paginationOptions={paginationOptions}
          />
        </Security>
      </div>
    );
  }
}

EntityStixCoreRelationships.propTypes = {
  entityId: PropTypes.string,
  role: PropTypes.string,
  targetStixDomainObjectTypes: PropTypes.array,
  relationshipTypes: PropTypes.array,
  entityLink: PropTypes.string,
  classes: PropTypes.object,
  t: PropTypes.func,
  history: PropTypes.object,
  exploreLink: PropTypes.string,
  isRelationReversed: PropTypes.bool,
  allDirections: PropTypes.bool,
  noState: PropTypes.bool,
};

export default compose(
  inject18n,
  withStyles(styles),
)(EntityStixCoreRelationships);
