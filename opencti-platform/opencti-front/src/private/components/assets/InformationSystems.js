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
import InformationSystemFormCreation from './informationSystem/InformationSystemFormCreation';
import InformationSystemGraphCreation from './informationSystem/InformationSystemGraphCreation';
import InformationSystemDeletion from './informationSystem/InformationSystemDeletion';
import InformationSystemEdition from './informationSystem/InformationSystemEdition';
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
      InfoSystemCreation: '',
      displayEdit: false,
      selectedInfoSystemId: '',
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
      InfoSystemCreation,
    } = this.state;
    const paginationOptions = {
      sortBy,
      orderAsc,
      filters: [],
      InfoSystemCreation,
    };
    if (this.props.history.location.pathname !== '/defender_hq/assets/information_systems'
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

  handleInformationSystemCreation(type) {
    this.setState({ InfoSystemCreation: type });
  }

  handleRefresh() {
    this.props.history.push('/defender_hq/assets/information_systems');
  }

  handleDisplayEdit(selectedElements) {
    let infoSystemId = '';
    if (selectedElements) {
      infoSystemId = (Object.entries(selectedElements)[0][1])?.id;
    }
    this.setState({ displayEdit: !this.state.displayEdit, selectedInfoSystemId: infoSystemId });
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
      risks: {
        label: 'Risks',
      },
      status: {
        label: 'Status',
      },
      label_name: {
        label: 'Labels',
      },
      severity: {
        label: 'Severity',
      },
      critical_system: {
        label: 'Critical System',
      },
      privacy_sensitive: {
        label: 'Privacy Sensitive',
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
        handleNewCreation={this.handleInformationSystemCreation.bind(this)}
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
      risks: {
        label: 'Risks',
        width: '6%',
        isSortable: true,
      },
      severity: {
        label: 'Severity',
        width: '8%',
        isSortable: true,
      },
      critical_system: {
        label: 'Critical System',
        width: '6%',
        isSortable: true,
      },
      sensitivity_level: {
        label: 'Sensitivity Level',
        width: '8%',
        isSortable: true,
      },
      privacy_sensitive: {
        label: 'Privacy Sensitive',
        width: '8%',
        isSortable: true,
      },
      status: {
        label: 'Status',
        width: '15%',
        isSortable: false,
      },
      label_name: {
        label: 'Labels',
        width: '20%',
        isSortable: true,
      },
      date_created: {
        label: 'Date Created',
        width: '10%',
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
        handleNewCreation={this.handleInformationSystemCreation.bind(this)}
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
      InfoSystemCreation,
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
        {view === 'cards' && this.renderCards(paginationOptions)}
        {view === 'lines' && this.renderLines(paginationOptions)}
        <InformationSystemFormCreation
          InfoSystemCreation={InfoSystemCreation === 'form'}
          handleInformationSystemCreation={this.handleInformationSystemCreation.bind(this)}
        />
        <InformationSystemGraphCreation
          InfoSystemCreation={InfoSystemCreation === 'graph'}
          handleInformationSystemCreation={this.handleInformationSystemCreation.bind(this)}
        />
        {this.state.selectedInfoSystemId && (
          <InformationSystemEdition
            displayEdit={this.state.displayEdit}
            history={this.props.history}
            informationSystemId={this.state.selectedInfoSystemId}
            handleDisplayEdit={this.handleDisplayEdit.bind(this)}
          />
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
