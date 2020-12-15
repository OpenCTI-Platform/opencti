import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import {
  compose, includes, pipe, assoc, propOr,
} from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import Drawer from '@material-ui/core/Drawer';
import Grid from '@material-ui/core/Grid';
import Select from '@material-ui/core/Select';
import Input from '@material-ui/core/Input';
import Chip from '@material-ui/core/Chip';
import MenuItem from '@material-ui/core/MenuItem';
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

const styles = (theme) => ({
  container: {
    marginTop: 15,
    paddingBottom: 70,
  },
  bottomNav: {
    zIndex: 1000,
    padding: '10px 200px 10px 205px',
    backgroundColor: theme.palette.navBottom.background,
    display: 'flex',
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
      toType: propOr('All', 'toType', params),
      numberOfElements: { number: 0, symbol: '' },
      openToType: false,
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

  handleOpenToType() {
    this.setState({ openToType: true });
  }

  handleCloseToType() {
    this.setState({ openToType: false });
  }

  handleChangeEntities(event) {
    const { value } = event.target;

    return this.setState({ openToType: false, toType: value }, () => this.saveView());
  }

  renderLines(paginationOptions) {
    const { sortBy, orderAsc } = this.state;
    const { entityLink, isRelationReversed } = this.props;
    const dataColumns = {
      relationship_type: {
        label: 'Relationship type',
        width: '15%',
        isSortable: false,
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
        label: 'Confidence level',
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
      >
        <QueryRenderer
          query={
            isRelationReversed
              ? entityStixCoreRelationshipsLinesToQuery
              : entityStixCoreRelationshipsLinesFromQuery
          }
          variables={{ count: 25, ...paginationOptions }}
          render={({ props }) => (isRelationReversed ? (
              <EntityStixCoreRelationshipsLinesTo
                data={props}
                paginationOptions={paginationOptions}
                entityLink={entityLink}
                dataColumns={dataColumns}
                initialLoading={props === null}
              />
          ) : (
              <EntityStixCoreRelationshipsLinesFrom
                data={props}
                paginationOptions={paginationOptions}
                entityLink={entityLink}
                dataColumns={dataColumns}
                initialLoading={props === null}
              />
          ))
          }
        />
      </ListLines>
    );
  }

  render() {
    const {
      t,
      classes,
      targetStixDomainObjectTypes,
      entityId,
      role,
      relationshipType,
      isRelationReversed,
      noBottomBar,
    } = this.props;

    const {
      view,
      searchTerm,
      toType,
      openToType,
      sortBy,
      orderAsc,
    } = this.state;

    // Display types selection when target types are multiple
    const displayTypes = targetStixDomainObjectTypes.length > 1
      || targetStixDomainObjectTypes.includes('Identity');
    const selectedTypes = toType === 'All' ? targetStixDomainObjectTypes : [toType];

    let paginationOptions = {
      relationship_type: relationshipType || 'stix-core-relationship',
      search: searchTerm,
      orderBy: sortBy,
      orderMode: orderAsc ? 'asc' : 'desc',
    };

    if (isRelationReversed) {
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
        {!noBottomBar ? (
          <Drawer
            anchor="bottom"
            variant="permanent"
            classes={{ paper: classes.bottomNav }}
          >
            <Grid container={true} spacing={1}>
              {displayTypes ? (
                <Grid item={true} xs="auto">
                  <Select
                    style={{ height: 50, marginRight: 15 }}
                    value={toType}
                    open={openToType}
                    onClose={this.handleCloseToType.bind(this)}
                    onOpen={this.handleOpenToType.bind(this)}
                    onChange={this.handleChangeEntities.bind(this)}
                    input={<Input id="entities" />}
                    renderValue={(selected) => (
                      <div className={classes.chips}>
                        <Chip
                          key={selected}
                          label={t(`entity_${selected}`)}
                          className={classes.chip}
                        />
                      </div>
                    )}
                  >
                    <MenuItem value="All">{t('All entities')}</MenuItem>
                    {includes('Attack-Pattern', targetStixDomainObjectTypes) ? (
                      <MenuItem value="Attack-Pattern">
                        {t('Attack pattern')}
                      </MenuItem>
                    ) : (
                      ''
                    )}
                    {includes('Campaign', targetStixDomainObjectTypes) ? (
                      <MenuItem value="Campaign">{t('Campaign')}</MenuItem>
                    ) : (
                      ''
                    )}
                    {includes('Note', targetStixDomainObjectTypes) ? (
                      <MenuItem value="Note">{t('Note')}</MenuItem>
                    ) : (
                      ''
                    )}
                    {includes('Observed-Data', targetStixDomainObjectTypes) ? (
                      <MenuItem value="Observed-Data">
                        {t('Observed data')}
                      </MenuItem>
                    ) : (
                      ''
                    )}
                    {includes('Opinion', targetStixDomainObjectTypes) ? (
                      <MenuItem value="Opinion">{t('Opinion')}</MenuItem>
                    ) : (
                      ''
                    )}
                    {includes('Report', targetStixDomainObjectTypes) ? (
                      <MenuItem value="Report">{t('Report')}</MenuItem>
                    ) : (
                      ''
                    )}
                    {includes(
                      'Course-Of-Action',
                      targetStixDomainObjectTypes,
                    ) ? (
                      <MenuItem value="Course-Of-Action">
                        {t('Course of action')}
                      </MenuItem>
                      ) : (
                        ''
                      )}
                    {includes('Individual', targetStixDomainObjectTypes)
                    || includes('Identity', targetStixDomainObjectTypes) ? (
                      <MenuItem value="Individual">{t('Individual')}</MenuItem>
                      ) : (
                        ''
                      )}
                    {includes('Organization', targetStixDomainObjectTypes)
                    || includes('Identity', targetStixDomainObjectTypes) ? (
                      <MenuItem value="Organization">
                        {t('Organization')}
                      </MenuItem>
                      ) : (
                        ''
                      )}
                    {includes('Sector', targetStixDomainObjectTypes)
                    || includes('Identity', targetStixDomainObjectTypes) ? (
                      <MenuItem value="Sector">{t('Sector')}</MenuItem>
                      ) : (
                        ''
                      )}
                    {includes('Indicator', targetStixDomainObjectTypes)
                    || includes('Indicator', targetStixDomainObjectTypes) ? (
                      <MenuItem value="Indicator">{t('Indicator')}</MenuItem>
                      ) : (
                        ''
                      )}
                    {includes('Infrastructure', targetStixDomainObjectTypes)
                    || includes('Infrastructure', targetStixDomainObjectTypes) ? (
                      <MenuItem value="Infrastructure">
                        {t('Infrastructure')}
                      </MenuItem>
                      ) : (
                        ''
                      )}
                    {includes('Intrusion-Set', targetStixDomainObjectTypes) ? (
                      <MenuItem value="Intrusion-Set">
                        {t('Intrusion set')}
                      </MenuItem>
                    ) : (
                      ''
                    )}
                    {includes('City', targetStixDomainObjectTypes)
                    || includes('Location', targetStixDomainObjectTypes) ? (
                      <MenuItem value="City">{t('City')}</MenuItem>
                      ) : (
                        ''
                      )}
                    {includes('Country', targetStixDomainObjectTypes)
                    || includes('Location', targetStixDomainObjectTypes) ? (
                      <MenuItem value="Country">{t('Country')}</MenuItem>
                      ) : (
                        ''
                      )}
                    {includes('Region', targetStixDomainObjectTypes)
                    || includes('Location', targetStixDomainObjectTypes) ? (
                      <MenuItem value="Region">{t('Region')}</MenuItem>
                      ) : (
                        ''
                      )}
                    {includes('Position', targetStixDomainObjectTypes)
                    || includes('Position', targetStixDomainObjectTypes) ? (
                      <MenuItem value="Position">{t('Position')}</MenuItem>
                      ) : (
                        ''
                      )}
                    {includes('Malware', targetStixDomainObjectTypes) ? (
                      <MenuItem value="Malware">{t('Malware')}</MenuItem>
                    ) : (
                      ''
                    )}
                    {includes('Threat-Actor', targetStixDomainObjectTypes) ? (
                      <MenuItem value="Threat-Actor">
                        {t('Threat actor')}
                      </MenuItem>
                    ) : (
                      ''
                    )}
                    {includes('Tool', targetStixDomainObjectTypes) ? (
                      <MenuItem value="Tool">{t('Tool')}</MenuItem>
                    ) : (
                      ''
                    )}
                    {includes('Vulnerability', targetStixDomainObjectTypes) ? (
                      <MenuItem value="Vulnerability">
                        {t('Vulnerability')}
                      </MenuItem>
                    ) : (
                      ''
                    )}
                    {includes(
                      'X-OpenCTI-Incident',
                      targetStixDomainObjectTypes,
                    ) ? (
                      <MenuItem value="X-OpenCTI-Incident">
                        {t('Incident')}
                      </MenuItem>
                      ) : (
                        ''
                      )}
                  </Select>
                </Grid>
              ) : (
                ''
              )}
            </Grid>
          </Drawer>
        ) : (
          ''
        )}
        {view === 'lines' ? this.renderLines(paginationOptions) : ''}
        <Security needs={[KNOWLEDGE_KNUPDATE]}>
          <StixCoreRelationshipCreationFromEntity
            entityId={entityId}
            isRelationReversed={isRelationReversed}
            paddingRight={220}
            targetStixDomainObjectTypes={targetStixDomainObjectTypes}
            allowedRelationshipTypes={
              relationshipType ? [relationshipType] : null
            }
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
  entityLink: PropTypes.string,
  relationshipType: PropTypes.string,
  classes: PropTypes.object,
  t: PropTypes.func,
  history: PropTypes.object,
  exploreLink: PropTypes.string,
  isRelationReversed: PropTypes.bool,
  noBottomBar: PropTypes.bool,
  noState: PropTypes.bool,
};

export default compose(
  inject18n,
  withStyles(styles),
)(EntityStixCoreRelationships);
