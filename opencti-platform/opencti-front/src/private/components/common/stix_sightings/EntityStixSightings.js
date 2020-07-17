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
import { QueryRenderer } from '../../../../relay/environment';
import ListLines from '../../../../components/list_lines/ListLines';
import inject18n from '../../../../components/i18n';
import EntityStixSightingsLines, {
  entityStixSightingsLinesQuery,
} from './EntityStixSightingsLines';
import StixSightingCreationFromEntity from './StixSightingCreationFromEntity';
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

class EntityStixSightings extends Component {
  constructor(props) {
    super(props);
    this.state = {
      sortBy: 'first_seen',
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

  renderLines(paginationOptions) {
    const { sortBy, orderAsc } = this.state;
    const { entityLink } = this.props;
    // sort only when inferences are disabled or inferences are resolved
    const dataColumns = {
      negative: {
        label: 'Status',
        width: '10%',
        isSortable: true,
      },
      number: {
        label: 'Count',
        width: '5%',
        isSortable: true,
      },
      name: {
        label: 'Name',
        width: '20%',
        isSortable: false,
      },
      entity_type: {
        label: 'Entity type',
        width: '15%',
        isSortable: false,
      },
      first_seen: {
        label: 'First obs.',
        width: '15%',
        isSortable: true,
      },
      last_seen: {
        label: 'Last obs.',
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
          query={entityStixSightingsLinesQuery}
          variables={{ count: 25, ...paginationOptions }}
          render={({ props }) => (
            <EntityStixSightingsLines
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
      t, classes, targetEntityTypes, entityId,
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
      toTypes: toType === 'All' ? targetEntityTypes : [toType],
      inferred: inferred && sortBy === null ? inferred : false,
      search: searchTerm,
      orderBy: sortBy,
      orderMode: orderAsc ? 'asc' : 'desc',
    };

    return (
      <div className={classes.container}>
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
                  {includes('Region', targetEntityTypes)
                  || includes('Identity', targetEntityTypes) ? (
                    <MenuItem value="Region">{t('Region')}</MenuItem>
                    ) : (
                      ''
                    )}
                  {includes('Country', targetEntityTypes)
                  || includes('Identity', targetEntityTypes) ? (
                    <MenuItem value="Country">{t('Country')}</MenuItem>
                    ) : (
                      ''
                    )}
                  {includes('City', targetEntityTypes)
                  || includes('Identity', targetEntityTypes) ? (
                    <MenuItem value="City">{t('City')}</MenuItem>
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
                  {includes('User', targetEntityTypes)
                  || includes('Identity', targetEntityTypes) ? (
                    <MenuItem value="User">{t('Individual')}</MenuItem>
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
        {view === 'lines' ? this.renderLines(paginationOptions) : ''}
        <Security needs={[KNOWLEDGE_KNUPDATE]}>
          <StixSightingCreationFromEntity
            entityId={entityId}
            isFrom={true}
            paddingRight={false}
            targetEntityTypes={targetEntityTypes}
            paginationOptions={paginationOptions}
          />
        </Security>
      </div>
    );
  }
}

EntityStixSightings.propTypes = {
  entityId: PropTypes.string,
  targetEntityTypes: PropTypes.array,
  entityLink: PropTypes.string,
  classes: PropTypes.object,
  reportClass: PropTypes.string,
  t: PropTypes.func,
  history: PropTypes.object,
  exploreLink: PropTypes.string,
};

export default compose(inject18n, withStyles(styles))(EntityStixSightings);
