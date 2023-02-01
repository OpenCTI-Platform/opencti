import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { withRouter } from 'react-router-dom';
import * as R from 'ramda';
import { QueryRenderer } from '../../../relay/environment';
import {
  buildViewParamsFromUrlAndStorage,
  convertFilters,
  saveViewParameters,
} from '../../../utils/ListParameters';
import inject18n from '../../../components/i18n';
import CyioListCards from '../../../components/list_cards/CyioListCards';
import CyioListLines from '../../../components/list_lines/CyioListLines';
import InformationSystemCards, {
  informationSystemCardsQuery,
} from './informationSystem/InformationSystemCards';
import InformationSystemLines, {
  informationSystemLinesQuery,
} from './informationSystem/InformationSystemLines';
import SoftwareCreation from './informationSystem/InformationSystemCreation';
import InformationSystemDeletion from './informationSystem/InformationSystemDeletion';
import { isUniqFilter } from '../common/lists/Filters';
import { toastGenericError } from '../../../utils/bakedToast';

class InformationSystems extends Component {
  constructor(props) {
    super(props);
    const params = buildViewParamsFromUrlAndStorage(
      props.history,
      props.location,
      'view-informationSystem',
    );
    this.state = {
      sortBy: R.propOr('name', 'sortBy', params),
      orderAsc: R.propOr(true, 'orderAsc', params),
      searchTerm: R.propOr('', 'searchTerm', params),
      view: R.propOr('lines', 'view', params),
      filters: R.propOr({}, 'filters', params),
      openExports: false,
      numberOfElements: { number: 0, symbol: '' },
      selectedElements: null,
      selectAll: false,
      openInfoSystemCreation: false,
    };
  }

  saveView() {
    this.handleRefresh();
    saveViewParameters(
      this.props.history,
      this.props.location,
      'view-informationSystem',
      this.state,
    );
  }

  componentWillUnmount() {
    const {
      sortBy,
      orderAsc,
      openInfoSystemCreation,
    } = this.state;
    const paginationOptions = {
      sortBy,
      orderAsc,
      filters: [],
      openInfoSystemCreation,
    };
    if (this.props.history.location.pathname !== '/defender HQ/assets/information_systems'
      && convertFilters(this.state.filters).length) {
      saveViewParameters(
        this.props.history,
        this.props.location,
        'view-informationSystem',
        paginationOptions,
      );
    }
  }

  handleChangeView(mode) {
    this.setState({ view: mode }, () => this.saveView());
  }

  handleSearch(value) {
    this.setState({ searchTerm: value }, () => this.saveView());
  }

  handleSort(field, orderAsc) {
    this.setState({ sortBy: field, orderAsc }, () => this.saveView());
  }

  handleToggleExports() {
    this.setState({ openExports: !this.state.openExports });
  }

  handleToggleSelectAll() {
    this.setState({ selectAll: !this.state.selectAll, selectedElements: null });
  }

  handleClearSelectedElements() {
    this.setState({ selectAll: false, selectedElements: null });
  }

  handleSoftwareCreation() {
    this.setState({ openInfoSystemCreation: true });
  }

  handleRefresh() {
    this.props.history.push('/defender HQ/assets/information_systems');
  }

  handleDisplayEdit(selectedElements) {
    const softwareId = Object.entries(selectedElements)[0][1].id;
    this.props.history.push({
      pathname: `/defender HQ/assets/information_systems/${softwareId}`,
      openEdit: true,
    });
  }

  handleToggleSelectEntity(entity, event) {
    event.stopPropagation();
    event.preventDefault();
    const { selectedElements } = this.state;
    if (entity.id in (selectedElements || {})) {
      const newSelectedElements = R.omit([entity.id], selectedElements);
      this.setState({
        selectAll: false,
        selectedElements: newSelectedElements,
      });
    } else {
      const newSelectedElements = R.assoc(
        entity.id,
        entity,
        selectedElements || {},
      );
      this.setState({
        selectAll: false,
        selectedElements: newSelectedElements,
      });
    }
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
        }, () => this.saveView(),
      );
    } else {
      this.setState(
        {
          filters: R.assoc(key, [{ id, value }], this.state.filters),
        }, () => this.saveView(),
      );
    }
  }

  handleRemoveFilter(key) {
    this.setState({ filters: R.dissoc(key, this.state.filters) }, () => this.saveView());
  }

  setNumberOfElements(numberOfElements) {
    this.setState({ numberOfElements });
  }

  renderCards(paginationOptions) {
    const {
      sortBy,
      orderAsc,
      selectAll,
      searchTerm,
      filters,
      openExports,
      selectedElements,
      numberOfElements,
    } = this.state;
    const dataColumns = {
      name: {
        label: 'Name',
      },
      asset_type: {
        label: 'Type',
      },
      vendor_name: {
        label: 'Vendor',
      },
      label_name: {
        label: 'Labels',
      },
    };
    return (
      <CyioListCards
        sortBy={sortBy}
        orderAsc={orderAsc}
        dataColumns={dataColumns}
        handleSort={this.handleSort.bind(this)}
        handleSearch={this.handleSearch.bind(this)}
        handleChangeView={this.handleChangeView.bind(this)}
        handleAddFilter={this.handleAddFilter.bind(this)}
        handleRemoveFilter={this.handleRemoveFilter.bind(this)}
        handleToggleExports={this.handleToggleExports.bind(this)}
        handleToggleSelectAll={this.handleToggleSelectAll.bind(this)}
        handleClearSelectedElements={this.handleClearSelectedElements.bind(this)}
        handleNewCreation={this.handleSoftwareCreation.bind(this)}
        handleDisplayEdit={this.handleDisplayEdit.bind(this)}
        selectedElements={selectedElements}
        selectAll={selectAll}
        OperationsComponent={<InformationSystemDeletion />}
        openExports={openExports}
        filterEntityType="InformationSystems"
        keyword={searchTerm}
        filters={filters}
        paginationOptions={paginationOptions}
        numberOfElements={numberOfElements}
        availableFilterKeys={[
          'name_m',
          'asset_type_or',
          'created_start_date',
          'created_end_date',
          'vendor_name_or',
          'label_name',
        ]}
      >
        <QueryRenderer
          query={informationSystemCardsQuery}
          variables={{ first: 50, offset: 0, ...paginationOptions }}
          render={({ error, props }) => {
            if (error) {
              toastGenericError('Request Failed');
            }
            return (
              <InformationSystemCards
                data={props}
                selectAll={selectAll}
                paginationOptions={paginationOptions}
                initialLoading={props === null}
                selectedElements={selectedElements}
                onLabelClick={this.handleAddFilter.bind(this)}
                onToggleEntity={this.handleToggleSelectEntity.bind(this)}
                setNumberOfElements={this.setNumberOfElements.bind(this)}
              />
            );
          }}
        />
      </CyioListCards>
    );
  }

  renderLines(paginationOptions) {
    const {
      sortBy,
      filters,
      orderAsc,
      selectAll,
      searchTerm,
      openExports,
      selectedElements,
      numberOfElements,
    } = this.state;
    const dataColumns = {
      name: {
        label: 'Name',
        width: '15%',
        isSortable: true,
      },
      asset_type: {
        label: 'Type',
        width: '8%',
        isSortable: true,
      },
      vendor_name: {
        label: 'Vendor',
        width: '10%',
        isSortable: true,
      },
      version: {
        label: 'Version',
        width: '10%',
        isSortable: false,
      },
      cpe_identifier: {
        label: 'CPE ID',
        width: '19%',
        isSortable: true,
      },
      software_identifier: {
        label: 'SWID',
        width: '15%',
        isSortable: true,
      },
      label_name: {
        label: 'Labels',
        width: '23%',
        isSortable: true,
      },
    };
    return (
      <CyioListLines
        sortBy={sortBy}
        orderAsc={orderAsc}
        dataColumns={dataColumns}
        handleSort={this.handleSort.bind(this)}
        handleSearch={this.handleSearch.bind(this)}
        handleChangeView={this.handleChangeView.bind(this)}
        handleAddFilter={this.handleAddFilter.bind(this)}
        handleRemoveFilter={this.handleRemoveFilter.bind(this)}
        handleToggleExports={this.handleToggleExports.bind(this)}
        handleToggleSelectAll={this.handleToggleSelectAll.bind(this)}
        handleClearSelectedElements={this.handleClearSelectedElements.bind(this)}
        handleNewCreation={this.handleSoftwareCreation.bind(this)}
        handleDisplayEdit={this.handleDisplayEdit.bind(this)}
        selectedElements={selectedElements}
        selectAll={selectAll}
        OperationsComponent={<InformationSystemDeletion />}
        openExports={openExports}
        filterEntityType="InformationSystems"
        keyword={searchTerm}
        filters={filters}
        paginationOptions={paginationOptions}
        numberOfElements={numberOfElements}
        availableFilterKeys={[
          'name_m',
          'asset_type_or',
          'created_start_date',
          'created_end_date',
          'vendor_name_or',
          'label_name',
        ]}
      >
        <QueryRenderer
          query={informationSystemLinesQuery}
          variables={{ first: 50, offset: 0, ...paginationOptions }}
          render={({ error, props }) => {
            if (error) {
              toastGenericError('Request Failed');
            }
            return (
              <InformationSystemLines
                data={props}
                selectAll={selectAll}
                dataColumns={dataColumns}
                initialLoading={props === null}
                selectedElements={selectedElements}
                paginationOptions={paginationOptions}
                onLabelClick={this.handleAddFilter.bind(this)}
                onToggleEntity={this.handleToggleSelectEntity.bind(this)}
                setNumberOfElements={this.setNumberOfElements.bind(this)}
              />
            );
          }}
        />
      </CyioListLines>
    );
  }

  render() {
    const {
      view,
      sortBy,
      orderAsc,
      searchTerm,
      filters,
      openInfoSystemCreation,
    } = this.state;
    const finalFilters = convertFilters(filters);
    const paginationOptions = {
      search: searchTerm,
      orderedBy: sortBy,
      orderMode: orderAsc ? 'asc' : 'desc',
      filters: finalFilters,
      filterMode: 'and',
    };
    const { location } = this.props;
    return (
      <div>
        {view === 'cards' && (!openInfoSystemCreation && !location.openNewCreation) ? this.renderCards(paginationOptions) : ''}
        {view === 'lines' && (!openInfoSystemCreation && !location.openNewCreation) ? this.renderLines(paginationOptions) : ''}
        {(openInfoSystemCreation || location.openNewCreation) && (
          // <Security needs={[KNOWLEDGE_KNUPDATE]}>
          <SoftwareCreation paginationOptions={paginationOptions} history={this.props.history} />
          // </Security>
        )}
      </div>
    );
  }
}

InformationSystems.propTypes = {
  t: PropTypes.func,
  history: PropTypes.object,
  location: PropTypes.object,
};

export default R.compose(inject18n, withRouter)(InformationSystems);
