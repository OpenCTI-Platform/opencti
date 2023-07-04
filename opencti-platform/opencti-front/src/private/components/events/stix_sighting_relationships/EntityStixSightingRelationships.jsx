import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import withStyles from '@mui/styles/withStyles';
import * as R from 'ramda';
import { QueryRenderer } from '../../../../relay/environment';
import ListLines from '../../../../components/list_lines/ListLines';
import inject18n from '../../../../components/i18n';
import EntityStixSightingRelationshipsLines, {
  entityStixSightingRelationshipsLinesQuery,
} from './EntityStixSightingRelationshipsLines';
import StixSightingRelationshipCreationFromEntity from './StixSightingRelationshipCreationFromEntity';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';
import { isUniqFilter } from '../../../../utils/filters/filtersUtils';
import {
  buildViewParamsFromUrlAndStorage,
  convertFilters,
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
    let params = {};
    if (!props.noState) {
      params = buildViewParamsFromUrlAndStorage(
        props.history,
        props.location,
        `view-sightings-${props.entityId}-${props.stixCoreObjectTypes?.join(
          '-',
        )}`,
      );
    }
    this.state = {
      sortBy: R.propOr('first_seen', 'sortBy', params),
      orderAsc: R.propOr(false, 'orderAsc', params),
      searchTerm: R.propOr('', 'searchTerm', params),
      view: R.propOr('lines', 'view', params),
      filters: R.propOr({}, 'filters', params),
      numberOfElements: { number: 0, symbol: '' },
      openExports: false,
    };
  }

  saveView() {
    if (!this.props.noState) {
      saveViewParameters(
        this.props.history,
        this.props.location,
        `view-sightings-${
          this.props.entityId
        }-${this.props.stixCoreObjectTypes?.join('-')}`,
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

  handleAddFilter(key, id, value, event = null) {
    if (event) {
      event.stopPropagation();
      event.preventDefault();
    }
    if (this.state.filters[key] && this.state.filters[key].length > 0) {
      this.setState(
        {
          filters: R.assoc(
            key,
            isUniqFilter(key)
              ? [{ id, value }]
              : R.uniqBy(R.prop('id'), [
                { id, value },
                ...this.state.filters[key],
              ]),
            this.state.filters,
          ),
        },
        () => this.saveView(),
      );
    } else {
      this.setState(
        {
          filters: R.assoc(key, [{ id, value }], this.state.filters),
        },
        () => this.saveView(),
      );
    }
  }

  handleRemoveFilter(key) {
    this.setState({ filters: R.dissoc(key, this.state.filters) }, () => this.saveView());
  }

  handleToggleExports() {
    this.setState({ openExports: !this.state.openExports });
  }

  renderLines(paginationOptions) {
    const { sortBy, orderAsc, openExports, disableExport, filters } = this.state;
    const { entityLink, isTo, stixCoreObjectTypes } = this.props;
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
        handleAddFilter={this.handleAddFilter.bind(this)}
        handleRemoveFilter={this.handleRemoveFilter.bind(this)}
        handleToggleExports={
          disableExport ? null : this.handleToggleExports.bind(this)
        }
        filters={filters}
        availableFilterKeys={[
          'toTypes',
          'labelledBy',
          'markedBy',
          'x_opencti_workflow_id',
          'created_start_date',
          'created_end_date',
          'createdBy',
          'x_opencti_negative',
        ]}
        openExports={openExports}
        exportEntityType="stix-sighting-relationship"
        availableEntityTypes={stixCoreObjectTypes}
        displayImport={true}
        secondaryAction={true}
        paginationOptions={paginationOptions}
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
    const { classes, stixCoreObjectTypes, entityId, isTo, noPadding } = this.props;
    const { view, searchTerm, sortBy, orderAsc, filters } = this.state;
    let finalFilters = convertFilters(filters);
    const toTypes = R.head(finalFilters.filter((n) => n.key === 'toTypes'))?.values || null;
    finalFilters = finalFilters.filter((n) => !['toTypes'].includes(n.key));
    const paginationOptions = {
      search: searchTerm,
      orderBy: sortBy,
      orderMode: orderAsc ? 'asc' : 'desc',
      filters: finalFilters,
      toTypes,
    };
    if (isTo) {
      paginationOptions.toId = entityId;
    } else {
      paginationOptions.fromId = entityId;
    }
    return (
      <div className={classes.container}>
        {view === 'lines' ? this.renderLines(paginationOptions) : ''}
        <Security needs={[KNOWLEDGE_KNUPDATE]}>
          {isTo ? (
            <StixSightingRelationshipCreationFromEntity
              entityId={entityId}
              isTo={true}
              stixCoreObjectTypes={[
                'Theat-Actor-Group',
                'Intrusion-Set',
                'Campaign',
                'Malware',
                'Tool',
                'Vulnerability',
                'Indicator',
              ]}
              targetStixCyberObservableTypes={['Stix-Cyber-Observable']}
              paddingRight={noPadding ? null : 220}
              paginationOptions={paginationOptions}
            />
          ) : (
            <StixSightingRelationshipCreationFromEntity
              entityId={entityId}
              stixCoreObjectTypes={stixCoreObjectTypes}
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
  stixCoreObjectTypes: PropTypes.array,
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
