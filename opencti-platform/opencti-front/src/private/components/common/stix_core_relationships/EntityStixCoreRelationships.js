import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose, includes } from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import Drawer from '@material-ui/core/Drawer';
import Grid from '@material-ui/core/Grid';
import Select from '@material-ui/core/Select';
import Input from '@material-ui/core/Input';
import Chip from '@material-ui/core/Chip';
import MenuItem from '@material-ui/core/MenuItem';
import FormControlLabel from '@material-ui/core/FormControlLabel';
import Switch from '@material-ui/core/Switch';
import { QueryRenderer } from '../../../../relay/environment';
import ListLines from '../../../../components/list_lines/ListLines';
import inject18n from '../../../../components/i18n';
import EntityStixCoreRelationshipsLines, {
  entityStixCoreRelationshipsLinesQuery,
} from './EntityStixCoreRelationshipsLines';
import StixCoreRelationshipCreationFromEntity from './StixCoreRelationshipCreationFromEntity';
import Security, { KNOWLEDGE_KNUPDATE } from '../../../../utils/Security';

const styles = (theme) => ({
  container: {
    marginTop: 15,
    paddingBottom: 70,
  },
  bottomNav: {
    zIndex: 1000,
    padding: '10px 274px 10px 84px',
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
    this.state = {
      sortBy: 'start_time',
      orderAsc: true,
      searchTerm: '',
      openToType: false,
      toType: 'All',
      inferred: false,
      view: 'lines',
    };
  }

  handleSort(field, orderAsc) {
    this.setState({ sortBy: field, orderAsc });
  }

  handleSearch(value) {
    this.setState({ searchTerm: value });
  }

  handleOpenToType() {
    this.setState({ openToType: true });
  }

  handleCloseToType() {
    this.setState({ openToType: false });
  }

  handleChangeEntities(event) {
    const { value } = event.target;
    if (value === 'All' && this.props.targetEntityTypes.length > 1) {
      return this.setState({
        openToType: false,
        toType: 'All',
      });
    }
    return this.setState({ openToType: false, toType: value });
  }

  handleChangeInferred() {
    this.setState({
      inferred: !this.state.inferred,
      sortBy: !this.state.inferred ? null : this.state.sortBy,
    });
  }

  renderLines(paginationOptions) {
    const { sortBy, orderAsc } = this.state;
    const { entityLink } = this.props;
    // sort only when inferences are disabled or inferences are resolved
    const dataColumns = {
      name: {
        label: 'Name',
        width: '30%',
        isSortable: false,
      },
      entity_type: {
        label: 'Entity type',
        width: '20%',
        isSortable: false,
      },
      start_time: {
        label: 'Start time',
        width: '15%',
        isSortable: true,
      },
      stop_time: {
        label: 'Stop time',
        width: '15%',
        isSortable: true,
      },
      confidence: {
        label: 'Confidence level',
        width: '15%',
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
          query={entityStixCoreRelationshipsLinesQuery}
          variables={{ count: 25, ...paginationOptions }}
          render={({ props }) => (
            <EntityStixCoreRelationshipsLines
              data={props}
              paginationOptions={paginationOptions}
              entityLink={entityLink}
              dataColumns={dataColumns}
              initialLoading={props === null}
            />
          )}
        />
      </ListLines>
    );
  }

  render() {
    const {
      t,
      classes,
      targetEntityTypes,
      entityId,
      role,
      relationshipType,
      creationIsFrom,
      noBottomBar,
      inference,
    } = this.props;
    const {
      view,
      searchTerm,
      toType,
      openToType,
      sortBy,
      orderAsc,
      inferred,
    } = this.state;

    // Display types selection when target types are multiple
    const displayTypes = targetEntityTypes.length > 1 || targetEntityTypes.includes('Identity');

    // sort only when inferences are disabled or inferences are resolved
    const paginationOptions = {
      fromId: entityId,
      fromRole: role || null,
      toTypes: toType === 'All' ? targetEntityTypes : [toType],
      inferred: !!(inferred || inference),
      relationship_type: relationshipType,
      search: searchTerm,
      orderBy: sortBy,
      orderMode: orderAsc ? 'asc' : 'desc',
    };

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
                          label={t(`entity_${selected.toLowerCase()}`)}
                          className={classes.chip}
                        />
                      </div>
                    )}
                  >
                    <MenuItem value="All">{t('All entities')}</MenuItem>
                    {includes('Attack-Pattern', targetEntityTypes) ? (
                      <MenuItem value="Attack-Pattern">
                        {t('Attack pattern')}
                      </MenuItem>
                    ) : (
                      ''
                    )}
                    {includes('Campaign', targetEntityTypes) ? (
                      <MenuItem value="Campaign">{t('Campaign')}</MenuItem>
                    ) : (
                      ''
                    )}
                    {includes('Note', targetEntityTypes) ? (
                      <MenuItem value="Note">{t('Note')}</MenuItem>
                    ) : (
                      ''
                    )}
                    {includes('Observed-Data', targetEntityTypes) ? (
                      <MenuItem value="Observed-Data">
                        {t('Observed data')}
                      </MenuItem>
                    ) : (
                      ''
                    )}
                    {includes('Opinion', targetEntityTypes) ? (
                      <MenuItem value="Opinion">{t('Opinion')}</MenuItem>
                    ) : (
                      ''
                    )}
                    {includes('Report', targetEntityTypes) ? (
                      <MenuItem value="Report">{t('Report')}</MenuItem>
                    ) : (
                      ''
                    )}
                    {includes('Course-Of-Action', targetEntityTypes) ? (
                      <MenuItem value="Course-Of-Action">
                        {t('Course of action')}
                      </MenuItem>
                    ) : (
                      ''
                    )}
                    {includes('Individual', targetEntityTypes)
                    || includes('Identity', targetEntityTypes) ? (
                      <MenuItem value="Individual">{t('Individual')}</MenuItem>
                      ) : (
                        ''
                      )}
                    {includes('Organization', targetEntityTypes)
                    || includes('Identity', targetEntityTypes) ? (
                      <MenuItem value="Organization">
                        {t('Organization')}
                      </MenuItem>
                      ) : (
                        ''
                      )}
                    {includes('Sector', targetEntityTypes)
                    || includes('Identity', targetEntityTypes) ? (
                      <MenuItem value="Sector">{t('Sector')}</MenuItem>
                      ) : (
                        ''
                      )}
                    {includes('Indicator', targetEntityTypes)
                    || includes('Indicator', targetEntityTypes) ? (
                      <MenuItem value="Indicator">{t('Indicator')}</MenuItem>
                      ) : (
                        ''
                      )}
                    {includes('Infrastructure', targetEntityTypes)
                    || includes('Infrastructure', targetEntityTypes) ? (
                      <MenuItem value="Infrastructure">
                        {t('Infrastructure')}
                      </MenuItem>
                      ) : (
                        ''
                      )}
                    {includes('Intrusion-Set', targetEntityTypes) ? (
                      <MenuItem value="Intrusion-Set">
                        {t('Intrusion set')}
                      </MenuItem>
                    ) : (
                      ''
                    )}
                    {includes('City', targetEntityTypes)
                    || includes('Location', targetEntityTypes) ? (
                      <MenuItem value="City">{t('City')}</MenuItem>
                      ) : (
                        ''
                      )}
                    {includes('Country', targetEntityTypes)
                    || includes('Location', targetEntityTypes) ? (
                      <MenuItem value="Country">{t('Country')}</MenuItem>
                      ) : (
                        ''
                      )}
                    {includes('Region', targetEntityTypes)
                    || includes('Location', targetEntityTypes) ? (
                      <MenuItem value="Region">{t('Region')}</MenuItem>
                      ) : (
                        ''
                      )}
                    {includes('Position', targetEntityTypes)
                    || includes('Position', targetEntityTypes) ? (
                      <MenuItem value="Position">{t('Position')}</MenuItem>
                      ) : (
                        ''
                      )}
                    {includes('Malware', targetEntityTypes) ? (
                      <MenuItem value="Malware">{t('Malware')}</MenuItem>
                    ) : (
                      ''
                    )}
                    {includes('Threat-Actor', targetEntityTypes) ? (
                      <MenuItem value="Threat-Actor">
                        {t('Threat actor')}
                      </MenuItem>
                    ) : (
                      ''
                    )}
                    {includes('Tool', targetEntityTypes) ? (
                      <MenuItem value="Tool">{t('Tool')}</MenuItem>
                    ) : (
                      ''
                    )}
                    {includes('Vulnerability', targetEntityTypes) ? (
                      <MenuItem value="Vulnerability">
                        {t('Vulnerability')}
                      </MenuItem>
                    ) : (
                      ''
                    )}
                    {includes('X-OpenCTI-Incident', targetEntityTypes) ? (
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
              <Grid item={true} xs="auto">
                <FormControlLabel
                  style={{ paddingTop: 5, marginRight: 15 }}
                  control={
                    <Switch
                      checked={inferred}
                      onChange={this.handleChangeInferred.bind(this)}
                      color="primary"
                    />
                  }
                  label={t('Inferences')}
                />
              </Grid>
            </Grid>
          </Drawer>
        ) : (
          ''
        )}
        {view === 'lines' ? this.renderLines(paginationOptions) : ''}
        <Security needs={[KNOWLEDGE_KNUPDATE]}>
          <StixCoreRelationshipCreationFromEntity
            entityId={entityId}
            isFrom={creationIsFrom}
            paddingRight={true}
            targetEntityTypes={targetEntityTypes}
            allowedRelationshipTypes={[relationshipType]}
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
  targetEntityTypes: PropTypes.array,
  entityLink: PropTypes.string,
  relationshipType: PropTypes.string,
  classes: PropTypes.object,
  t: PropTypes.func,
  history: PropTypes.object,
  exploreLink: PropTypes.string,
  creationIsFrom: PropTypes.bool,
  noBottomBar: PropTypes.bool,
  inference: PropTypes.bool,
};

export default compose(
  inject18n,
  withStyles(styles),
)(EntityStixCoreRelationships);
