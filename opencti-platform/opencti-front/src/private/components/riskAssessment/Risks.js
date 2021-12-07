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
import CyioListCards from '../../../components/list_cards/CyioListCards';
import CyioListLines from '../../../components/list_lines/CyioListLines';
import RisksCards, {
  risksCardsQuery,
} from './risks/RisksCards';
import RisksLines, {
  risksLinesQuery,
} from './risks/RisksLines';
import RiskCreation from './risks/RiskCreation';
import Security, { KNOWLEDGE_KNUPDATE } from '../../../utils/Security';
import { isUniqFilter } from '../common/lists/Filters';
import RiskDeletion from './risks/RiskDeletion';

class Risks extends Component {
  constructor(props) {
    super(props);
    const params = buildViewParamsFromUrlAndStorage(
      props.history,
      props.location,
      'view-risks',
    );
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
      openRiskCreation: false,
    };
  }

  saveView() {
    saveViewParameters(
      this.props.history,
      this.props.location,
      'view-risks',
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

  handleRiskCreation() {
    this.setState({ openRiskCreation: true });
  }

  handleDisplayEdit(selectedElements) {
    const riskId = Object.entries(selectedElements)[0][1].id;
    this.props.history.push({
      pathname: `/dashboard/risk-assessment/risks/${riskId}`,
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
        handleNewCreation={this.handleRiskCreation.bind(this)}
        handleDisplayEdit={this.handleDisplayEdit.bind(this)}
        selectedElements={selectedElements}
        selectAll={selectAll}
        CreateItemComponent={<RiskCreation />}
        OperationsComponent={<RiskDeletion />}
        openExports={openExports}
        exportEntityType="Risk"
        keyword={searchTerm}
        filters={filters}
        paginationOptions={paginationOptions}
        numberOfElements={numberOfElements}
        availableFilterKeys={[
          'markedBy',
          'created_start_date',
          'created_end_date',
          'createdBy',
          'labelledBy',
        ]}
      >
        <QR
          environment={QueryRendererDarkLight}
          query={risksCardsQuery}
          variables={{ count: 25, ...paginationOptions }}
          render={({ error, props }) => <RisksCards
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
          }
        />
        {/* <QueryRenderer
          query={risksCardsQuery}
          variables={{ count: 25, ...paginationOptions }}
          render={({ error, props }) => {
            console.log(`DarkLightRisksCards Error ${error} OR Props ${JSON.stringify(props)}`);
            return (
              <RisksCards
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
        /> */}
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
    let numberOfSelectedElements = Object.keys(selectedElements || {}).length;
    if (selectAll) {
      numberOfSelectedElements = numberOfElements.original;
    }
    const dataColumns = {
      id: {
        label: 'ID',
        width: '11%',
        isSortable: true,
      },
      priority: {
        label: 'Priority',
        width: '8%',
        isSortable: false,
      },
      risk: {
        label: 'Risk',
        width: '9%',
        isSortable: true,
      },
      status: {
        label: 'Status',
        width: '17%',
        isSortable: true,
      },
      response: {
        label: 'Response',
        width: '11%',
        isSortable: true,
      },
      lifecycle: {
        label: 'Lifecycle',
        width: '11%',
        isSortable: true,
      },
      component: {
        label: 'Component',
        width: '11%',
        isSortable: true,
      },
      asset: {
        label: 'Asset',
        width: '11%',
        isSortable: true,
      },
      deadline: {
        label: 'Deadline',
        width: '11%',
        isSortable: false,
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
        handleNewCreation={this.handleRiskCreation.bind(this)}
        handleDisplayEdit={this.handleDisplayEdit.bind(this)}
        selectedElements={selectedElements}
        CreateItemComponent={<RiskCreation />}
        OperationsComponent={<RiskDeletion />}
        openExports={openExports}
        selectAll={selectAll}
        exportEntityType="Risk"
        keyword={searchTerm}
        filters={filters}
        paginationOptions={paginationOptions}
        numberOfElements={numberOfElements}
        availableFilterKeys={[
          'assetTypeBy',
          'labelledBy',
          'release_date',
          // 'markedBy',
          // 'created_start_date',
          'operation_status',
          'operation_System',
          // 'created_end_date',
          // 'createdBy',
          'labelledBy',
        ]}
      >
        <QR
          environment={QueryRendererDarkLight}
          query={risksLinesQuery}
          variables={{ count: 25, ...paginationOptions }}
          render={({ error, props }) => {
            console.log(`props : ${props} Error : ${error}`);
            return (<RisksLines
                data={props}
                selectAll={selectAll}
                dataColumns={dataColumns}
                initialLoading={props === null}
                selectedElements={selectedElements}
                paginationOptions={paginationOptions}
                onLabelClick={this.handleAddFilter.bind(this)}
                onToggleEntity={this.handleToggleSelectEntity.bind(this)}
                setNumberOfElements={this.setNumberOfElements.bind(this)}
              />);
          }
          }
        />
        {/* <QueryRenderer
          query={risksLinesQuery}
          variables={{ count: 25, ...paginationOptions }}
          render={({ error, props }) => {
            console.log(`DarkLight Error ${error} OR Props ${JSON.stringify(props)}`);
            return (
              <RisksLines
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
        /> */}
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
      openRiskCreation,
    } = this.state;
    const finalFilters = convertFilters(filters);
    const paginationOptions = {
      search: searchTerm,
      orderedBy: sortBy,
      orderMode: orderAsc ? 'asc' : 'desc',
      filters: finalFilters,
    };
    const { location } = this.props;
    return (
      <div>
        {view === 'cards' && (!openRiskCreation && !location.openNewCreation) ? this.renderCards(paginationOptions) : ''}
        {view === 'lines' && (!openRiskCreation && !location.openNewCreation) ? this.renderLines(paginationOptions) : ''}
        {((openRiskCreation || location.openNewCreation) && (
          // <Security needs={[KNOWLEDGE_KNUPDATE]}>
          <RiskCreation paginationOptions={paginationOptions} history={this.props.history} />
          // </Security>
        ))}
      </div>
    );
  }
}

Risks.propTypes = {
  t: PropTypes.func,
  history: PropTypes.object,
  location: PropTypes.object,
};

export default R.compose(inject18n, withRouter)(Risks);
