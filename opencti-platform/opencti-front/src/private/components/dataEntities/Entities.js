import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { withRouter } from 'react-router-dom';
import * as R from 'ramda';
import Typography from '@material-ui/core/Typography';
import {
  buildViewParamsFromUrlAndStorage,
  convertFilters,
  saveViewParameters,
} from '../../../utils/ListParameters';
import inject18n from '../../../components/i18n';
import CyioListCards from '../../../components/list_cards/CyioListCards';
import CyioListLines from '../../../components/list_lines/CyioListLines';
import EntitiesCreation from './data/EntitiesCreation';
import { isUniqFilter } from '../common/lists/Filters';
import EntitiesDeletion from './data/EntitiesDeletion';

class Entities extends Component {
  constructor(props) {
    super(props);
    const params = buildViewParamsFromUrlAndStorage(
      props.history,
      props.location,
      'view-data',
    );
    this.state = {
      sortBy: R.propOr('', 'sortBy', params),
      orderAsc: R.propOr(true, 'orderAsc', params),
      searchTerm: R.propOr('', 'searchTerm', params),
      view: R.propOr('cards', 'view', params),
      filters: R.propOr({}, 'filters', params),
      openExports: false,
      numberOfElements: { number: 0, symbol: '' },
      selectedElements: null,
      selectAll: false,
      openDataCreation: false,
    };
  }

  saveView() {
    this.handleRefresh();
    saveViewParameters(
      this.props.history,
      this.props.location,
      'view-data',
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
    this.setState({ openDataCreation: true });
  }

  handleRefresh() {
    this.props.history.push('/data/entities');
  }

  handleDisplayEdit(selectedElements) {
    const riskId = Object.entries(selectedElements)[0][1].id;
    this.props.history.push({
      pathname: `/activities/risk_assessment/risks/${riskId}`,
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
      );
    } else {
      this.setState(
        {
          filters: R.assoc(key, [{ id, value }], this.state.filters),
        },
      );
    }
  }

  handleRemoveFilter(key) {
    this.setState({ filters: R.dissoc(key, this.state.filters) });
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
    const {
      t,
    } = this.props;
    const dataColumns = {
      type: {
        label: 'Type',
      },
      name: {
        label: 'Name',
      },
      author: {
        label: 'Author',
      },
      labels: {
        label: 'Labels',
      },
      creation_date: {
        label: 'Creation Date',
      },
      marking: {
        label: 'Marking',
      },
    };
    return (
      <CyioListCards
        sortBy={sortBy}
        orderAsc={orderAsc}
        dataColumns={dataColumns}
        disabled={true}
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
        CreateItemComponent={<EntitiesCreation />}
        OperationsComponent={<EntitiesDeletion />}
        openExports={openExports}
        filterEntityType="Entities"
        keyword={searchTerm}
        filters={filters}
        paginationOptions={paginationOptions}
        numberOfElements={numberOfElements}
        availableFilterKeys={[
          'created_start_date',
          'created_end_date',
          'label_name',
        ]}
      >
        <div style={{ textAlign: 'left', margin: '100px auto', width: '500px' }}>
          <Typography style={{ fontSize: '40px' }} color='textSecondary'>{t('Select a Data Type')}</Typography>
          <Typography style={{ fontSize: '20px' }} color='textSecondary'>
            {t('Please choose from the Data Type dropdown above.')}
          </Typography>
        </div>
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
    const {
      t,
    } = this.props;
    const dataColumns = {
      type: {
        label: 'Type',
        width: '17%',
        isSortable: true,
      },
      name: {
        label: 'Name',
        width: '16%',
        isSortable: false,
      },
      author: {
        label: 'Author',
        width: '16%',
        isSortable: true,
      },
      labels: {
        label: 'Labels',
        width: '16%',
        isSortable: true,
      },
      creation_date: {
        label: 'Creation Date',
        width: '15%',
        isSortable: true,
      },
      marking: {
        label: 'Marking',
        width: '13%',
        isSortable: true,
      },
    };
    return (
      <CyioListLines
        sortBy={sortBy}
        orderAsc={orderAsc}
        dataColumns={dataColumns}
        noHeaders={true}
        disabled={true}
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
        CreateItemComponent={<EntitiesCreation />}
        OperationsComponent={<EntitiesDeletion />}
        openExports={openExports}
        selectAll={selectAll}
        filterEntityType="Entities"
        keyword={searchTerm}
        filters={filters}
        paginationOptions={paginationOptions}
        numberOfElements={numberOfElements}
        availableFilterKeys={[
          'created_start_date',
          'created_end_date',
          'label_name',
        ]}
      >
        <div style={{ textAlign: 'left', margin: '100px auto', width: '500px' }}>
          <Typography style={{ fontSize: '40px' }} color='textSecondary'>{t('Select a Data Type')}</Typography>
          <Typography style={{ fontSize: '20px' }} color='textSecondary'>
            {t('Please choose from the Data Type dropdown above.')}
          </Typography>
        </div>
      </CyioListLines>
    );
  }

  render() {
    const {
      view,
      orderAsc,
      searchTerm,
      filters,
      openDataCreation,
    } = this.state;
    const finalFilters = convertFilters(filters);
    const paginationOptions = {
      search: searchTerm,
      // orderedBy: sortBy,
      orderedBy: 'name',
      orderMode: orderAsc ? 'asc' : 'desc',
      filters: finalFilters,
      filterMode: 'and',
    };
    const { location } = this.props;
    return (
      <div>
        {view === 'cards' && (!openDataCreation && !location.openNewCreation) ? this.renderCards(paginationOptions) : ''}
        {view === 'lines' && (!openDataCreation && !location.openNewCreation) ? this.renderLines(paginationOptions) : ''}
        {((openDataCreation || location.openNewCreation) && (
          // <Security needs={[KNOWLEDGE_KNUPDATE]}>
          <EntitiesCreation paginationOptions={paginationOptions} history={this.props.history} />
          // </Security>
        ))}
      </div>
    );
  }
}

Entities.propTypes = {
  t: PropTypes.func,
  history: PropTypes.object,
  location: PropTypes.object,
};

export default R.compose(inject18n, withRouter)(Entities);
