import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { withRouter } from 'react-router-dom';
import * as R from 'ramda';
import { QueryRenderer as QR } from 'react-relay';
import { QueryRenderer } from '../../../relay/environment';
import QueryRendererDarkLight from '../../../relay/environmentDarkLight';
import {
  buildViewParamsFromUrlAndStorage,
  convertFilters,
  saveViewParameters,
} from '../../../utils/ListParameters';
import inject18n from '../../../components/i18n';
import ListCards from '../../../components/list_cards/ListCards';
import ListLines from '../../../components/list_lines/ListLines';
import DevicesCards, {
  devicesCardsQuery,
  // devicesCardsdarkLightRootQuery,
} from './devices/DevicesCards';
import DevicesLines, {
  devicesLinesQuery,
  devicesLinesdarkLightRootQuery,
} from './devices/DevicesLines';
import DeviceCreation from './devices/DeviceCreation';
import Security, { KNOWLEDGE_KNUPDATE } from '../../../utils/Security';
import { isUniqFilter } from '../common/lists/Filters';
import DeviceDeletion from './devices/DeviceDeletion';

class Devices extends Component {
  constructor(props) {
    super(props);
    const params = buildViewParamsFromUrlAndStorage(
      props.history,
      props.location,
      'view-devices',
    );
    console.log('sdassfasfasparams', params);
    this.state = {
      sortBy: R.propOr('name', 'sortBy', params),
      orderAsc: R.propOr(true, 'orderAsc', params),
      searchTerm: R.propOr('', 'searchTerm', params),
      view: R.propOr('cards', 'view', params),
      filters: R.propOr({}, 'filters', params),
      openExports: false,
      numberOfElements: { number: 0, symbol: '' },
      selectedElements: null,
      selectAll: false,
      openDeviceCreation: false,
    };
  }

  saveView() {
    saveViewParameters(
      this.props.history,
      this.props.location,
      'view-devices',
      this.state,
    );
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

  handleDeleteElements() {
    console.log('deleted successfully', this.state.selectedElements);
  }

  handleDeviceCreation() {
    this.setState({ openDeviceCreation: true });
  }

  handleDisplayEdit() {
    this.props.history.push({
      pathname: `/dashboard/assets/devices/${'id'}`,
      state: { openNewCreation: true },
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

      created: {
        label: 'Creation date',
      },
      modified: {
        label: 'Modification date',
      },
    };
    return (
      <ListCards
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
        handleDisplayEdit={this.handleDisplayEdit.bind(this)}
        selectedElements={selectedElements}
        selectAll={selectAll}
        CreateItemComponent={<DeviceCreation />}
        OperationsComponent={<DeviceDeletion />}
        openExports={openExports}
        exportEntityType="Device"
        keyword={searchTerm}
        filters={filters}
        paginationOptions={paginationOptions}
        numberOfElements={numberOfElements}
        availableFilterKeys={[
          'asset_type',
          'labelledBy',
          'markedBy',
          'created_start_date',
          'created_end_date',
          'createdBy',
        ]}
      >
        {/* <QueryRenderer
          query={devicesCardsQuery}
          variables={{ count: 25, ...paginationOptions }}
          render={({ props }) => (
            <DevicesCards
              data={props}
              extra={props}
              paginationOptions={paginationOptions}
              initialLoading={props === null}
              onLabelClick={this.handleAddFilter.bind(this)}
              setNumberOfElements={this.setNumberOfElements.bind(this)}
            />
          )}
        /> */}
        <QR
          environment={QueryRendererDarkLight}
          query={devicesCardsQuery}
          variables={{ count: 25, ...paginationOptions }}
          render={({ error, props }) => {
            console.log(`DarkLightDevicesCards Error ${error} OR Props ${JSON.stringify(props)}`);
            return (
              <DevicesCards
                data={props}
                extra={props}
                paginationOptions={paginationOptions}
                initialLoading={props === null}
                onLabelClick={this.handleAddFilter.bind(this)}
                setNumberOfElements={this.setNumberOfElements.bind(this)}
              />
            );
          }}
        />
      </ListCards>
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
    let numberOfSelectedElements = Object.keys(selectedElements || {}).length;
    if (selectAll) {
      numberOfSelectedElements = numberOfElements.original;
    }
    const dataColumns = {
      name: {
        label: 'Name',
        width: '12%',
        isSortable: true,
      },
      type: {
        label: 'Type',
        width: '8%',
        isSortable: true,
      },
      assetId: {
        label: 'Asset ID',
        width: '12%',
        isSortable: true,
      },
      ipAddress: {
        label: 'IP Address',
        width: '12%',
        isSortable: true,
      },
      fqdn: {
        label: 'FQDN',
        width: '12%',
        isSortable: true,
      },
      os: {
        label: 'OS',
        width: '8%',
        isSortable: true,
      },
      networkId: {
        label: 'Network ID',
        width: '12%',
        isSortable: true,
      },
      objectLabel: {
        label: 'Label',
        width: '20%',
        isSortable: false,
      },
    };
    return (
      <ListLines
        sortBy={sortBy}
        orderAsc={orderAsc}
        dataColumns={dataColumns}
        handleSort={this.handleSort.bind(this)}
        handleSearch={this.handleSearch.bind(this)}
        handleChangeView={this.handleChangeView.bind(this)}
        handleAddFilter={this.handleAddFilter.bind(this)}
        handleRemoveFilter={this.handleRemoveFilter.bind(this)}
        handleToggleExports={this.handleToggleExports.bind(this)}
        handleDeleteElements={this.handleDeleteElements.bind(this)}
        handleToggleSelectAll={this.handleToggleSelectAll.bind(this)}
        handleNewCreation={this.handleDeviceCreation.bind(this)}
        handleDisplayEdit={this.handleDisplayEdit.bind(this)}
        selectedElements={selectedElements}
        CreateItemComponent={<DeviceCreation />}
        OperationsComponent={<DeviceDeletion />}
        openExports={openExports}
        selectAll={selectAll}
        exportEntityType="Device"
        keyword={searchTerm}
        filters={filters}
        paginationOptions={paginationOptions}
        numberOfElements={numberOfElements}
        availableFilterKeys={[
          'labelledBy',
          'markedBy',
          'created_start_date',
          'created_end_date',
          'createdBy',
        ]}
      >
        {/* <QueryRenderer
          query={devicesLinesQuery}
          variables={{ count: 25, ...paginationOptions }}
          render={({ props }) => (
            <DevicesLines
              data={props}
              paginationOptions={paginationOptions}
              dataColumns={dataColumns}
              selectAll={selectAll}
              selectedElements={selectedElements}
              initialLoading={props === null}
              onLabelClick={this.handleAddFilter.bind(this)}
              onToggleEntity={this.handleToggleSelectEntity.bind(this)}
              setNumberOfElements={this.setNumberOfElements.bind(this)}
            />
          )}
        /> */}
        <QR
          environment={QueryRendererDarkLight}
          query={devicesLinesQuery}
          variables={{ count: 25, ...paginationOptions }}
          render={({ error, props }) => {
            console.log(`DarkLight Error ${error} OR Props ${JSON.stringify(props)}`);
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
      </ListLines>
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
      orderBy: sortBy,
      orderMode: orderAsc ? 'asc' : 'desc',
      filters: finalFilters,
    };
    const { location } = this.props;
    return (
      <div>
        {view === 'cards' && (!openDeviceCreation && !location.openNewCreation) ? this.renderCards(paginationOptions) : ''}
        {view === 'lines' && (!openDeviceCreation && !location.openNewCreation) ? this.renderLines(paginationOptions) : ''}
        {((openDeviceCreation || location.openNewCreation) && (
            <Security needs={[KNOWLEDGE_KNUPDATE]}>
              <DeviceCreation paginationOptions={paginationOptions} history={this.props.history} />
            </Security>
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
