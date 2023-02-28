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
import DevicesCards, {
  devicesCardsQuery,
} from './devices/DevicesCards';
import DevicesLines, {
  devicesLinesQuery,
} from './devices/DevicesLines';
import DeviceCreation from './devices/DeviceCreation';
import { isUniqFilter } from '../common/lists/Filters';
import DeviceDeletion from './devices/DeviceDeletion';
import { toastGenericError } from '../../../utils/bakedToast';

class Devices extends Component {
  constructor(props) {
    super(props);
    const params = buildViewParamsFromUrlAndStorage(
      props.history,
      props.location,
      'view-devices',
    );
    this.state = {
      sortBy: R.propOr('top_risk_severity', 'sortBy', params),
      orderAsc: R.propOr(false, 'orderAsc', params),
      searchTerm: R.propOr('', 'searchTerm', params),
      view: R.propOr('lines', 'view', params),
      filters: R.propOr({}, 'filters', params),
      openExports: false,
      numberOfElements: { number: 0, symbol: '' },
      selectedElements: null,
      selectAll: false,
      openDeviceCreation: false,
    };
  }

  saveView() {
    this.handleRefresh();
    saveViewParameters(
      this.props.history,
      this.props.location,
      'view-devices',
      this.state,
    );
  }

  componentWillUnmount() {
    const {
      sortBy,
      orderAsc,
      openDeviceCreation,
    } = this.state;
    const paginationOptions = {
      sortBy,
      orderAsc,
      filters: [],
      openDeviceCreation,
    };
    if (this.props.history.location.pathname !== '/defender_hq/assets/devices'
      && convertFilters(this.state.filters).length) {
      saveViewParameters(
        this.props.history,
        this.props.location,
        'view-devices',
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

  handleDeviceCreation() {
    this.setState({ openDeviceCreation: true });
  }

  handleRefresh() {
    this.props.history.push('/defender_hq/assets/devices');
  }

  handleDisplayEdit(selectedElements) {
    const deviceId = Object.entries(selectedElements)[0][1].id;
    this.props.history.push({
      pathname: `/defender_hq/assets/devices/${deviceId}`,
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
      searchTerm,
      filters,
      openExports,
      numberOfElements,
      selectedElements,
      selectAll,
    } = this.state;
    const dataColumns = {
      name: {
        label: 'Name',
      },
      asset_type: {
        label: 'Type',
      },
      asset_id: {
        label: 'Asset ID',
      },
      ip_address_value: {
        label: 'IP Address',
      },
      installed_os_name: {
        label: 'OS',
      },
      network_id: {
        label: 'Network ID',
      },
      label_name: {
        label: 'Label',
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
        handleNewCreation={this.handleDeviceCreation.bind(this)}
        handleClearSelectedElements={this.handleClearSelectedElements.bind(this)}
        handleDisplayEdit={this.handleDisplayEdit.bind(this)}
        selectedElements={selectedElements}
        selectAll={selectAll}
        OperationsComponent={<DeviceDeletion />}
        openExports={openExports}
        filterEntityType="Device"
        keyword={searchTerm}
        filters={filters}
        paginationOptions={paginationOptions}
        numberOfElements={numberOfElements}
        availableFilterKeys={[
          'name_m',
          'asset_type_or',
          'created_start_date',
          'created_end_date',
          'label_name',
        ]}
      >
        <QueryRenderer
          query={devicesCardsQuery}
          variables={{ first: 50, offset: 0, ...paginationOptions }}
          render={({ error, props }) => {
            if (error) {
              toastGenericError('Request Failed');
            }
            return (
              <DevicesCards
                data={props}
                extra={props}
                selectAll={selectAll}
                paginationOptions={paginationOptions}
                initialLoading={props === null}
                selectedElements={selectedElements}
                onLabelClick={this.handleAddFilter.bind(this)}
                setNumberOfElements={this.setNumberOfElements.bind(this)}
                onToggleEntity={this.handleToggleSelectEntity.bind(this)}
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
      risk_count: {
        label: 'Risks',
        width: '5%',
        isSortable: true,
      },
      top_risk_severity: {
        label: 'Severity',
        width: '12%',
        isSortable: true,
      },
      asset_type: {
        label: 'Type',
        width: '5%',
        isSortable: true,
      },
      asset_id: {
        label: 'Asset ID',
        width: '12%',
        isSortable: true,
      },
      ip_address_value: {
        label: 'IP Address',
        width: '12%',
        isSortable: true,
      },
      fqdn: {
        label: 'FQDN',
        width: '12%',
        isSortable: false,
      },
      installed_os_name: {
        label: 'OS',
        width: '5%',
        isSortable: true,
      },
      network_id: {
        label: 'Network ID',
        width: '12%',
        isSortable: true,
      },
      label_name: {
        label: 'Label',
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
        handleNewCreation={this.handleDeviceCreation.bind(this)}
        handleDisplayEdit={this.handleDisplayEdit.bind(this)}
        selectedElements={selectedElements}
        OperationsComponent={<DeviceDeletion />}
        openExports={openExports}
        selectAll={selectAll}
        filterEntityType="Device"
        keyword={searchTerm}
        filters={filters}
        paginationOptions={paginationOptions}
        numberOfElements={numberOfElements}
        availableFilterKeys={[
          'name_m',
          'asset_type_or',
          'created_start_date',
          'created_end_date',
          'label_name',
        ]}
      >
        <QueryRenderer
          query={devicesLinesQuery}
          variables={{ first: 50, offset: 0, ...paginationOptions }}
          render={({ error, props }) => {
            if (error) {
              toastGenericError('Request Failed');
            }
            return (
              <DevicesLines
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
      openDeviceCreation,
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
        {view === 'cards' && (!openDeviceCreation && !location.openNewCreation) ? this.renderCards(paginationOptions) : ''}
        {view === 'lines' && (!openDeviceCreation && !location.openNewCreation) ? this.renderLines(paginationOptions) : ''}
        {((openDeviceCreation || location.openNewCreation) && (
          // <Security needs={[KNOWLEDGE_KNUPDATE]}>
          <DeviceCreation paginationOptions={paginationOptions} history={this.props.history} />
          // </Security>
        ))}
      </div>
    );
  }
}

Devices.propTypes = {
  t: PropTypes.func,
  history: PropTypes.object,
  location: PropTypes.object,
};

export default R.compose(inject18n, withRouter)(Devices);
