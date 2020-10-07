import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import {
  append, assoc, dissoc, filter, map, propOr,
} from 'ramda';
import StixDomainObjectIndicatorsLines, {
  stixDomainObjectIndicatorsLinesQuery,
} from './StixDomainObjectIndicatorsLines';
import ListLines from '../../../../components/list_lines/ListLines';
import { QueryRenderer } from '../../../../relay/environment';
import StixCoreRelationshipCreationFromEntity from '../../common/stix_core_relationships/StixCoreRelationshipCreationFromEntity';
import {
  buildViewParamsFromUrlAndStorage,
  convertFilters,
  saveViewParameters,
} from '../../../../utils/ListParameters';
import IndicatorsRightBar from './IndicatorsRightBar';
import Security, { KNOWLEDGE_KNUPDATE } from '../../../../utils/Security';

class StixDomainObjectIndicators extends Component {
  constructor(props) {
    super(props);
    const params = buildViewParamsFromUrlAndStorage(
      props.history,
      props.location,
      `view-indicators-${props.stixDomainObjectId}`,
    );
    this.state = {
      sortBy: propOr('created_at', 'sortBy', params),
      orderAsc: propOr(false, 'orderAsc', params),
      searchTerm: propOr('', 'searchTerm', params),
      view: propOr('lines', 'view', params),
      filters: propOr({}, 'filters', params),
      indicatorTypes: [],
      observableTypes: [],
      openExports: false,
      inferred: false,
      numberOfElements: { number: 0, symbol: '' },
    };
  }

  saveView() {
    saveViewParameters(
      this.props.history,
      this.props.location,
      `view-indicators-${this.props.stixDomainObjectId}`,
      this.state,
    );
  }

  handleSearch(value) {
    this.setState({ searchTerm: value }, () => this.saveView());
  }

  handleSort(field, orderAsc) {
    this.setState({ sortBy: field, orderAsc }, () => this.saveView());
  }

  handleToggleExports() {
    this.setState({ openExports: !this.state.openExports }, () => {
      if (typeof this.props.onChangeOpenExports === 'function') {
        this.props.onChangeOpenExports(this.state.openExports);
      }
    });
  }

  handleToggleIndicatorType(type) {
    if (this.state.indicatorTypes.includes(type)) {
      this.setState({
        indicatorTypes: filter((t) => t !== type, this.state.indicatorTypes),
      });
    } else {
      this.setState({
        indicatorTypes: append(type, this.state.indicatorTypes),
      });
    }
  }

  handleToggleObservableType(type) {
    if (this.state.observableTypes.includes(type)) {
      this.setState({
        observableTypes: filter((t) => t !== type, this.state.observableTypes),
      });
    } else {
      this.setState({
        observableTypes: append(type, this.state.observableTypes),
      });
    }
  }

  handleAddFilter(key, id, value, event = null) {
    if (event) {
      event.stopPropagation();
      event.preventDefault();
    }
    this.setState(
      {
        filters: assoc(key, [{ id, value }], this.state.filters),
      },
      () => this.saveView(),
    );
  }

  handleRemoveFilter(key) {
    this.setState({ filters: dissoc(key, this.state.filters) }, () => this.saveView());
  }

  setNumberOfElements(numberOfElements) {
    this.setState({ numberOfElements });
  }

  renderLines(paginationOptions) {
    const {
      sortBy,
      orderAsc,
      searchTerm,
      openExports,
      numberOfElements,
      filters,
    } = this.state;
    const { stixDomainObjectId, stixDomainObjectLink } = this.props;
    const dataColumns = {
      toPatternType: {
        label: 'Type',
        width: '10%',
        isSortable: true,
      },
      toName: {
        label: 'Name',
        width: '30%',
        isSortable: true,
      },
      objectLabel: {
        label: 'Labels',
        width: '15%',
        isSortable: false,
      },
      created_at: {
        label: 'Creation date',
        width: '15%',
        isSortable: true,
      },
      toValidUntil: {
        label: 'Valid until',
        width: '15%',
        isSortable: true,
      },
      objectMarking: {
        label: 'Marking',
        isSortable: false,
      },
    };
    const orderByMapping = {
      toPatternType: 'pattern_type',
      toName: 'name',
      toValidFrom: 'valid_from',
      toValidUntil: 'valid_until',
      toCreatedAt: 'created_at',
    };
    const exportPaginationOptions = {
      filters: [{ key: 'indicates', values: [stixDomainObjectId] }],
      orderBy: orderByMapping[sortBy === 'start_time' ? 'toCreatedAt' : sortBy],
      orderMode: orderAsc ? 'asc' : 'desc',
      search: searchTerm,
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
        handleToggleExports={this.handleToggleExports.bind(this)}
        openExports={openExports}
        noPadding={typeof this.props.onChangeOpenExports === 'function'}
        paginationOptions={exportPaginationOptions}
        exportEntityType="Indicator"
        filters={filters}
        exportContext={`of-entity-${stixDomainObjectId}`}
        keyword={searchTerm}
        secondaryAction={true}
        numberOfElements={numberOfElements}
        availableFilterKeys={['toCreatedAt_start_date', 'toCreatedAt_end_date']}
      >
        <QueryRenderer
          query={stixDomainObjectIndicatorsLinesQuery}
          variables={{ count: 25, ...paginationOptions }}
          render={({ props }) => (
            <StixDomainObjectIndicatorsLines
              data={props}
              paginationOptions={paginationOptions}
              entityLink={stixDomainObjectLink}
              dataColumns={dataColumns}
              initialLoading={props === null}
              setNumberOfElements={this.setNumberOfElements.bind(this)}
            />
          )}
        />
      </ListLines>
    );
  }
  created_at
  render() {
    const { stixDomainObjectId, relationshipType } = this.props;
    const {
      view,
      sortBy,
      orderAsc,
      inferred,
      searchTerm,
      filters,
      indicatorTypes,
      observableTypes,
      openExports,
    } = this.state;
    let finalFilters = convertFilters(filters);
    if (indicatorTypes.length > 0) {
      finalFilters = append(
        { key: 'toPatternType', values: indicatorTypes },
        finalFilters,
      );
    }
    if (observableTypes.length > 0) {
      finalFilters = append(
        {
          key: 'toMainObservableType',
          operator: 'match',
          values: map(
            (type) => type.toLowerCase().replace('*', ''),
            observableTypes,
          ),
        },
        finalFilters,
      );
    }
    const paginationOptions = {
      inferred,
      search: searchTerm,
      toTypes: ["Indicator"],
      fromId: stixDomainObjectId,
      relationship_type: relationshipType || 'indicates',
      lastSeenStart: null,
      lastSeenStop: null,
      orderBy: sortBy,
      orderMode: orderAsc ? 'asc' : 'desc',
      filters: finalFilters,
    };
    return (
      <div style={{ marginTop: 20, paddingRight: 250 }}>
        {view === 'lines' ? this.renderLines(paginationOptions) : ''}
        <Security needs={[KNOWLEDGE_KNUPDATE]}>
          <StixCoreRelationshipCreationFromEntity
            entityId={stixDomainObjectId}
            isRelationReversed={true}
            targetStixDomainObjectTypes={['Indicator']}
            paginationOptions={paginationOptions}
            openExports={openExports}
            paddingRight={270}
          />
        </Security>
        <IndicatorsRightBar
          indicatorTypes={indicatorTypes}
          observableTypes={observableTypes}
          handleToggleIndicatorType={this.handleToggleIndicatorType.bind(this)}
          handleToggleObservableType={this.handleToggleObservableType.bind(
            this,
          )}
          openExports={openExports}
        />
      </div>
    );
  }
}

StixDomainObjectIndicators.propTypes = {
  stixDomainObjectId: PropTypes.string,
  stixDomainObjectLink: PropTypes.string,
  relationshipType: PropTypes.string,
  history: PropTypes.object,
  onChangeOpenExports: PropTypes.func,
};

export default StixDomainObjectIndicators;
