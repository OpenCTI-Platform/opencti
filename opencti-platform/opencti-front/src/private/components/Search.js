import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { withRouter } from 'react-router-dom';
import withStyles from '@mui/styles/withStyles';
import Typography from '@mui/material/Typography';
import * as R from 'ramda';
import { QueryRenderer } from '../../relay/environment';
import inject18n from '../../components/i18n';
import TopBar from './nav/TopBar';
import {
  buildViewParamsFromUrlAndStorage,
  convertFilters,
  saveViewParameters,
} from '../../utils/ListParameters';
import { isUniqFilter } from '../../utils/filters/filtersUtils';
import { UserContext } from '../../utils/hooks/useAuth';
import ListLines from '../../components/list_lines/ListLines';
import ToolBar from './data/ToolBar';
import SearchStixCoreObjectsLines, {
  searchStixCoreObjectsLinesQuery,
} from './search/SearchStixCoreObjectsLines';
import ExportContextProvider from '../../utils/ExportContextProvider';

const styles = () => ({
  container: {
    margin: 0,
  },
});

class Search extends Component {
  constructor(props) {
    super(props);
    const params = buildViewParamsFromUrlAndStorage(
      props.history,
      props.location,
      'view-search',
    );
    this.state = {
      sortBy: '_score',
      orderAsc: false,
      view: R.propOr('lines', 'view', params),
      filters: R.propOr({}, 'filters', params),
      numberOfElements: { number: 0, symbol: '' },
      selectedElements: null,
      deSelectedElements: null,
      selectAll: false,
      openExports: false,
    };
  }

  saveView() {
    saveViewParameters(
      this.props.history,
      this.props.location,
      'view-stix-domain-objects',
      this.state,
    );
  }

  handleChangeView(mode) {
    this.setState({ view: mode }, () => this.saveView());
  }

  handleSort(field, orderAsc) {
    this.setState({ sortBy: field, orderAsc });
  }

  handleToggleExports() {
    this.setState({ openExports: !this.state.openExports });
  }

  handleClearSelectedElements() {
    this.setState({
      selectAll: false,
      selectedElements: null,
      deSelectedElements: null,
    });
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

  handleToggleSelectEntity(entity, event) {
    event.stopPropagation();
    event.preventDefault();
    const { selectedElements, deSelectedElements, selectAll } = this.state;
    if (entity.id in (selectedElements || {})) {
      const newSelectedElements = R.omit([entity.id], selectedElements);
      this.setState({
        selectAll: false,
        selectedElements: newSelectedElements,
      });
    } else if (selectAll && entity.id in (deSelectedElements || {})) {
      const newDeSelectedElements = R.omit([entity.id], deSelectedElements);
      this.setState({
        deSelectedElements: newDeSelectedElements,
      });
    } else if (selectAll) {
      const newDeSelectedElements = R.assoc(
        entity.id,
        entity,
        deSelectedElements || {},
      );
      this.setState({
        deSelectedElements: newDeSelectedElements,
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

  handleToggleSelectAll() {
    this.setState({
      selectAll: !this.state.selectAll,
      selectedElements: null,
      deSelectedElements: null,
    });
  }

  // eslint-disable-next-line class-methods-use-this
  buildColumns(helper) {
    const isRuntimeSort = helper.isRuntimeFieldEnable();
    return {
      entity_type: {
        label: 'Type',
        width: '10%',
        isSortable: true,
      },
      value: {
        label: 'Value',
        width: '22%',
        isSortable: false,
      },
      createdBy: {
        label: 'Author',
        width: '12%',
        isSortable: isRuntimeSort,
      },
      creator: {
        label: 'Creator',
        width: '12%',
        isSortable: true,
      },
      objectLabel: {
        label: 'Labels',
        width: '16%',
        isSortable: false,
      },
      created_at: {
        label: 'Creation date',
        width: '10%',
        isSortable: true,
      },
      reports: {
        label: 'Reports',
        width: '8%',
        isSortable: false,
      },
      objectMarking: {
        label: 'Marking',
        isSortable: isRuntimeSort,
      },
    };
  }

  renderLines(paginationOptions) {
    const {
      sortBy,
      orderAsc,
      filters,
      numberOfElements,
      selectedElements,
      deSelectedElements,
      selectAll,
      openExports,
    } = this.state;
    const { search } = paginationOptions;
    let numberOfSelectedElements = Object.keys(selectedElements || {}).length;
    if (selectAll) {
      numberOfSelectedElements = numberOfElements.original
        - Object.keys(deSelectedElements || {}).length;
    }
    return (
      <UserContext.Consumer>
        {({ helper }) => (
          <div>
            <ListLines
              sortBy={sortBy}
              orderAsc={orderAsc}
              dataColumns={this.buildColumns(helper)}
              handleSort={this.handleSort.bind(this)}
              handleAddFilter={this.handleAddFilter.bind(this)}
              handleRemoveFilter={this.handleRemoveFilter.bind(this)}
              handleChangeView={this.handleChangeView.bind(this)}
              handleToggleSelectAll={this.handleToggleSelectAll.bind(this)}
              handleToggleExports={this.handleToggleExports.bind(this)}
              openExports={openExports}
              exportEntityType="Stix-Core-Object"
              selectAll={selectAll}
              disableCards={true}
              filters={filters}
              paginationOptions={paginationOptions}
              numberOfElements={numberOfElements}
              iconExtension={true}
              availableFilterKeys={[
                'entity_type',
                'markedBy',
                'labelledBy',
                'createdBy',
                'confidence',
                'x_opencti_organization_type',
                'created_start_date',
                'created_end_date',
                'created_at_start_date',
                'created_at_end_date',
                'creator',
              ]}
            >
              <QueryRenderer
                query={searchStixCoreObjectsLinesQuery}
                variables={{ count: 25, ...paginationOptions }}
                render={({ props }) => (
                  <SearchStixCoreObjectsLines
                    data={props}
                    paginationOptions={paginationOptions}
                    dataColumns={this.buildColumns(helper)}
                    initialLoading={props === null}
                    onLabelClick={this.handleAddFilter.bind(this)}
                    selectedElements={selectedElements}
                    deSelectedElements={deSelectedElements}
                    onToggleEntity={this.handleToggleSelectEntity.bind(this)}
                    selectAll={selectAll}
                    setNumberOfElements={this.setNumberOfElements.bind(this)}
                  />
                )}
              />
            </ListLines>
            <ToolBar
              selectedElements={selectedElements}
              deSelectedElements={deSelectedElements}
              numberOfSelectedElements={numberOfSelectedElements}
              selectAll={selectAll}
              filters={filters}
              search={search}
              handleClearSelectedElements={this.handleClearSelectedElements.bind(
                this,
              )}
            />
          </div>
        )}
      </UserContext.Consumer>
    );
  }

  render() {
    const {
      t,
      match: {
        params: { keyword },
      },
    } = this.props;
    const { view, sortBy, orderAsc, filters } = this.state;
    let searchTerm = '';
    try {
      searchTerm = decodeURIComponent(keyword || '');
    } catch (e) {
      // Do nothing
    }
    const finalFilters = convertFilters(filters);
    const paginationOptions = {
      search: searchTerm,
      filters: finalFilters,
      orderBy: sortBy,
      orderMode: orderAsc ? 'asc' : 'desc',
    };
    return (
      <ExportContextProvider>
      <div>
        <TopBar keyword={searchTerm} />
        <Typography
          variant="h1"
          gutterBottom={true}
          style={{ margin: '-5px 20px 0 0', float: 'left' }}
        >
          {t('Search for an entity')}
        </Typography>
        {view === 'lines' ? this.renderLines(paginationOptions) : ''}
      </div>
      </ExportContextProvider>
    );
  }
}

Search.propTypes = {
  keyword: PropTypes.string,
  classes: PropTypes.object,
  t: PropTypes.func,
  match: PropTypes.object,
  history: PropTypes.object,
};

export default R.compose(inject18n, withRouter, withStyles(styles))(Search);
