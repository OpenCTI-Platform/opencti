import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose, includes } from 'ramda';
import withStyles from '@mui/styles/withStyles';
import Drawer from '@mui/material/Drawer';
import Grid from '@mui/material/Grid';
import Select from '@mui/material/Select';
import MenuItem from '@mui/material/MenuItem';
import { QueryRenderer } from '../../../../relay/environment';
import ListLines from '../../../../components/list_lines/ListLines';
import inject18n from '../../../../components/i18n';
import EntityStixSightingRelationshipsLines, {
  entityStixSightingRelationshipsLinesQuery,
} from './EntityStixSightingRelationshipsLines';
import StixSightingRelationshipCreationFromEntity from './StixSightingRelationshipCreationFromEntity';
import Security, { KNOWLEDGE_KNUPDATE } from '../../../../utils/Security';

const styles = (theme) => ({
  container: {
    marginTop: 15,
    paddingBottom: 70,
  },
  bottomNav: {
    zIndex: 1000,
    padding: '10px 200px 10px 205px',
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

class EntityStixSightingRelationships extends Component {
  constructor(props) {
    super(props);
    this.state = {
      sortBy: 'first_seen',
      orderAsc: true,
      searchTerm: '',
      openToType: false,
      toType: 'All',
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
    if (value === 'All' && this.props.targetStixDomainObjectTypes.length > 1) {
      return this.setState({
        openToType: false,
        toType: 'All',
      });
    }
    return this.setState({ openToType: false, toType: value });
  }

  renderLines(paginationOptions) {
    const { sortBy, orderAsc } = this.state;
    const { entityLink, isTo } = this.props;
    // sort only when inferences are disabled or inferences are resolved
    const dataColumns = {
      x_opencti_negative: {
        label: 'Status',
        width: '10%',
        isSortable: true,
      },
      attribute_count: {
        label: 'Count',
        width: '10%',
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
          query={entityStixSightingRelationshipsLinesQuery}
          variables={{ count: 25, ...paginationOptions }}
          render={({ props }) => (
            <EntityStixSightingRelationshipsLines
              data={props}
              paginationOptions={paginationOptions}
              entityLink={entityLink}
              dataColumns={dataColumns}
              initialLoading={props === null}
              isTo={isTo}
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
      targetStixDomainObjectTypes,
      entityId,
      isTo,
      noPadding,
    } = this.props;
    const { view, searchTerm, toType, openToType, sortBy, orderAsc } = this.state;
    // Display types selection when target types are multiple
    const displayTypes = !isTo
      && (targetStixDomainObjectTypes.length > 1
        || targetStixDomainObjectTypes.includes('Identity'));
    // sort only when inferences are disabled or inferences are resolved
    const paginationOptions = {
      search: searchTerm,
      orderBy: sortBy,
      orderMode: orderAsc ? 'asc' : 'desc',
    };
    if (isTo) {
      paginationOptions.toId = entityId;
    } else {
      paginationOptions.fromId = entityId;
      paginationOptions.toTypes = toType === 'All' ? targetStixDomainObjectTypes : [toType];
    }
    return (
      <div className={classes.container}>
        {displayTypes && (
          <Drawer
            anchor="bottom"
            variant="permanent"
            classes={{ paper: classes.bottomNav }}
            PaperProps={{ variant: 'elevation', elevation: 1 }}
          >
            <Grid container={true} spacing={1}>
              <Grid item={true} xs="auto">
                <Select
                  variant="standard"
                  value={toType}
                  open={openToType}
                  onClose={this.handleCloseToType.bind(this)}
                  onOpen={this.handleOpenToType.bind(this)}
                  onChange={this.handleChangeEntities.bind(this)}
                >
                  <MenuItem value="All">{t('All entities')}</MenuItem>
                  {(includes('Region', targetStixDomainObjectTypes)
                    || includes('Identity', targetStixDomainObjectTypes)) && (
                    <MenuItem value="Region">{t('Region')}</MenuItem>
                  )}
                  {(includes('Country', targetStixDomainObjectTypes)
                    || includes('Identity', targetStixDomainObjectTypes)) && (
                    <MenuItem value="Country">{t('Country')}</MenuItem>
                  )}
                  {(includes('City', targetStixDomainObjectTypes)
                    || includes('Identity', targetStixDomainObjectTypes)) && (
                    <MenuItem value="City">{t('City')}</MenuItem>
                  )}
                  {(includes('Organization', targetStixDomainObjectTypes)
                    || includes('Identity', targetStixDomainObjectTypes)) && (
                    <MenuItem value="Organization">
                      {t('Organization')}
                    </MenuItem>
                  )}
                  {(includes('User', targetStixDomainObjectTypes)
                    || includes('Identity', targetStixDomainObjectTypes)) && (
                    <MenuItem value="User">{t('Individual')}</MenuItem>
                  )}
                </Select>
              </Grid>
            </Grid>
          </Drawer>
        )}
        {view === 'lines' ? this.renderLines(paginationOptions) : ''}
        <Security needs={[KNOWLEDGE_KNUPDATE]}>
          {isTo ? (
            <StixSightingRelationshipCreationFromEntity
              entityId={entityId}
              isTo={true}
              targetStixDomainObjectTypes={[
                'Threat-Actor',
                'Intrusion-Set',
                'Campaign',
                'Malware',
                'Tool',
              ]}
              targetStixCyberObservableTypes={['Stix-Cyber-Observable']}
              paddingRight={noPadding ? null : 220}
              paginationOptions={paginationOptions}
            />
          ) : (
            <StixSightingRelationshipCreationFromEntity
              entityId={entityId}
              targetStixDomainObjectTypes={targetStixDomainObjectTypes}
              paddingRight={noPadding ? null : 220}
              paginationOptions={paginationOptions}
            />
          )}
        </Security>
      </div>
    );
  }
}

EntityStixSightingRelationships.propTypes = {
  entityId: PropTypes.string,
  targetStixDomainObjectTypes: PropTypes.array,
  entityLink: PropTypes.string,
  classes: PropTypes.object,
  t: PropTypes.func,
  history: PropTypes.object,
  exploreLink: PropTypes.string,
  noPadding: PropTypes.bool,
  isTo: PropTypes.bool,
};

export default compose(
  inject18n,
  withStyles(styles),
)(EntityStixSightingRelationships);
