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
import ListLines from '../../../components/list_lines/ListLines';
import ReportsLines, { reportsLinesQuery } from './reports/ReportsLines';
import inject18n from '../../../components/i18n';
import ReportCreation from './reports/ReportCreation';
import ToolBar from '../data/ToolBar';
import { isUniqFilter } from '../common/lists/Filters';
import Security, {
  KNOWLEDGE_KNUPDATE,
  UserContext,
} from '../../../utils/Security';

class Reports extends Component {
  constructor(props) {
    super(props);
    const params = buildViewParamsFromUrlAndStorage(
      props.history,
      props.location,
      `view-reports${props.objectId ? `-${props.objectId}` : ''}`,
    );
    this.state = {
      sortBy: R.propOr('published', 'sortBy', params),
      orderAsc: R.propOr(false, 'orderAsc', params),
      searchTerm: R.propOr('', 'searchTerm', params),
      view: R.propOr('lines', 'view', params),
      filters: R.propOr({}, 'filters', params),
      openExports: false,
      numberOfElements: { number: 0, symbol: '' },
      selectedElements: null,
      deSelectedElements: null,
      selectAll: false,
    };
  }

  saveView() {
    saveViewParameters(
      this.props.history,
      this.props.location,
      `view-reports${this.props.objectId ? `-${this.props.objectId}` : ''}`,
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

  renderLines(paginationOptions, helper) {
    const {
      sortBy,
      orderAsc,
      searchTerm,
      filters,
      openExports,
      numberOfElements,
      selectedElements,
      deSelectedElements,
      selectAll,
    } = this.state;
    const { objectId, authorId } = this.props;
    let exportContext = null;
    if (objectId) {
      exportContext = `of-entity-${objectId}`;
    } else if (authorId) {
      exportContext = `of-entity-${authorId}`;
    }
    let numberOfSelectedElements = Object.keys(selectedElements || {}).length;
    if (selectAll) {
      numberOfSelectedElements = numberOfElements.original
        - Object.keys(deSelectedElements || {}).length;
    }
    let finalFilters = filters;
    finalFilters = R.assoc(
      'entity_type',
      [{ id: 'Report', value: 'Report' }],
      finalFilters,
    );
    const isRuntimeSort = helper.isRuntimeFieldEnable();
    const dataColumns = {
      name: {
        label: 'Title',
        width: '30%',
        isSortable: true,
      },
      createdBy: {
        label: 'Author',
        width: '15%',
        isSortable: isRuntimeSort,
      },
      objectLabel: {
        label: 'Labels',
        width: '20%',
        isSortable: false,
      },
      published: {
        label: 'Date',
        width: '10%',
        isSortable: true,
      },
      x_opencti_workflow_id: {
        label: 'Status',
        width: '10%',
        isSortable: true,
      },
      objectMarking: {
        label: 'Marking',
        isSortable: isRuntimeSort,
      },
    };
    return (
      <div>
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
          handleToggleSelectAll={this.handleToggleSelectAll.bind(this)}
          selectAll={selectAll}
          noPadding={typeof this.props.onChangeOpenExports === 'function'}
          exportEntityType="Report"
          exportContext={exportContext}
          keyword={searchTerm}
          filters={filters}
          paginationOptions={paginationOptions}
          numberOfElements={numberOfElements}
          iconExtension={true}
          availableFilterKeys={[
            'report_types',
            'confidence_gt',
            'x_opencti_workflow_id',
            'labelledBy',
            'createdBy',
            'markedBy',
            'published_start_date',
            'published_end_date',
          ]}
        >
          <QueryRenderer
            query={reportsLinesQuery}
            variables={{ count: 25, ...paginationOptions }}
            render={({ props }) => (
              <ReportsLines
                data={props}
                paginationOptions={paginationOptions}
                dataColumns={dataColumns}
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
          search={searchTerm}
          filters={finalFilters}
          handleClearSelectedElements={this.handleClearSelectedElements.bind(
            this,
          )}
          type="Report"
        />
      </div>
    );
  }

  render() {
    const {
      match: {
        params: { reportType },
      },
      objectId,
      authorId,
    } = this.props;
    const { view, sortBy, orderAsc, searchTerm, filters } = this.state;
    const reportFilterClass = reportType !== 'all' && reportType !== undefined
      ? reportType.replace(/_/g, ' ')
      : '';
    const finalFilters = convertFilters(filters);
    if (reportFilterClass) {
      finalFilters.push({
        key: 'report_types',
        values: [reportFilterClass],
      });
    }
    if (authorId) finalFilters.push({ key: 'createdBy', values: [authorId] });
    if (objectId) finalFilters.push({ key: 'objectContains', values: [objectId] });
    const paginationOptions = {
      filters: finalFilters,
      search: searchTerm,
      orderBy: sortBy,
      orderMode: orderAsc ? 'asc' : 'desc',
    };
    return (
      <UserContext.Consumer>
        {({ helper }) => (
          <div>
            {view === 'lines'
              ? this.renderLines(paginationOptions, helper)
              : ''}
            <Security needs={[KNOWLEDGE_KNUPDATE]}>
              <ReportCreation paginationOptions={paginationOptions} />
            </Security>
          </div>
        )}
      </UserContext.Consumer>
    );
  }
}

Reports.propTypes = {
  objectId: PropTypes.string,
  authorId: PropTypes.string,
  t: PropTypes.func,
  match: PropTypes.object,
  history: PropTypes.object,
  location: PropTypes.object,
  displayCreate: PropTypes.bool,
  onChangeOpenExports: PropTypes.func,
};

export default R.compose(inject18n, withRouter)(Reports);
