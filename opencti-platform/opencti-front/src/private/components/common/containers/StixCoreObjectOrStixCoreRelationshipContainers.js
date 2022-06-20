import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { withRouter } from 'react-router-dom';
import withStyles from '@mui/styles/withStyles';
import * as R from 'ramda';
import { last, map, toPairs } from 'ramda';
import Chip from '@mui/material/Chip';
import { QueryRenderer } from '../../../../relay/environment';
import {
  buildViewParamsFromUrlAndStorage,
  convertFilters,
  saveViewParameters,
} from '../../../../utils/ListParameters';
import ListLines from '../../../../components/list_lines/ListLines';
import StixCoreObjectOrStixCoreRelationshipContainersLines, {
  stixCoreObjectOrStixCoreRelationshipContainersLinesQuery,
} from './StixCoreObjectOrStixCoreRelationshipContainersLines';
import inject18n from '../../../../components/i18n';
import StixCoreObjectOrStixCoreRelationshipContainersGraph, {
  stixCoreObjectOrStixCoreRelationshipContainersGraphQuery,
} from './StixCoreObjectOrStixCoreRelationshipContainersGraph';
import Loader from '../../../../components/Loader';
import StixCoreObjectOrStixCoreRelationshipContainersGraphBar from './StixCoreObjectOrStixCoreRelationshipContainersGraphBar';
import Filters, { isUniqFilter } from '../lists/Filters';
import SearchInput from '../../../../components/SearchInput';
import { truncate } from '../../../../utils/String';
import { UserContext } from '../../../../utils/Security';

const VIEW_AS_KNOWLEDGE = 'knowledge';

const styles = (theme) => ({
  container: {
    marginTop: 20,
    paddingBottom: 70,
  },
  containerGraph: {
    marginTop: 20,
  },
  bottomNav: {
    zIndex: 1000,
    display: 'flex',
    overflow: 'hidden',
  },
  button: {
    marginRight: 10,
  },
  parameters: {
    marginTop: -10,
  },
  filters: {
    float: 'left',
    margin: '2px 0 0 10px',
  },
  filter: {
    marginRight: 10,
  },
  operator: {
    fontFamily: 'Consolas, monaco, monospace',
    backgroundColor: theme.palette.background.accent,
    marginRight: 10,
  },
});

class StixCoreObjectOrStixCoreRelationshipContainers extends Component {
  constructor(props) {
    super(props);
    this.params = buildViewParamsFromUrlAndStorage(
      props.history,
      props.location,
      `view-containers${
        props.stixDomainObjectOrStixCoreRelationship
          ? `-${props.stixDomainObjectOrStixCoreRelationship.id}`
          : `-${props.authorId}`
      }`,
    );
    this.state = {
      sortBy: R.propOr('created', 'sortBy', this.params),
      orderAsc: R.propOr(false, 'orderAsc', this.params),
      searchTerm: R.propOr('', 'searchTerm', this.params),
      view: R.propOr('lines', 'view', this.params),
      filters: R.propOr({}, 'filters', this.params),
      openExports: false,
      numberOfElements: { number: 0, symbol: '' },
      viewAs: R.propOr(VIEW_AS_KNOWLEDGE, 'viewAs', this.params),
    };
  }

  componentDidUpdate(prevProps) {
    if (prevProps.viewAs !== this.props.viewAs) {
      this.setState({ viewAs: this.props.viewAs }, () => this.saveView());
    }
  }

  saveView() {
    saveViewParameters(
      this.props.history,
      this.props.location,
      `view-containers${
        this.props.stixDomainObjectOrStixCoreRelationship
          ? `-${this.props.stixDomainObjectOrStixCoreRelationship.id}`
          : `-${this.props.authorId}`
      }`,
      this.state,
    );
  }

  saveViewParameters(params) {
    saveViewParameters(
      this.props.history,
      this.props.location,
      `view-containers${
        this.props.stixDomainObjectOrStixCoreRelationship
          ? `-${this.props.stixDomainObjectOrStixCoreRelationship.id}`
          : `-${this.props.authorId}`
      }`,
      { ...this.state, ...params },
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
    this.setState({ openExports: !this.state.openExports }, () => {
      if (typeof this.props.onChangeOpenExports === 'function') {
        this.props.onChangeOpenExports(this.state.openExports);
      }
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
            key === 'container_type' ? 'entity_type' : key,
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
          filters: R.assoc(
            key === 'container_type' ? 'entity_type' : key,
            [{ id, value }],
            this.state.filters,
          ),
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

  // eslint-disable-next-line class-methods-use-this
  buildColumns(helper) {
    const isRuntimeSort = helper.isRuntimeFieldEnable();
    return {
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
      created: {
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
  }

  renderLines(paginationOptions) {
    const {
      sortBy,
      orderAsc,
      searchTerm,
      filters,
      openExports,
      numberOfElements,
    } = this.state;
    const { stixDomainObjectOrStixCoreRelationship, authorId } = this.props;
    let exportContext = null;
    if (stixDomainObjectOrStixCoreRelationship) {
      exportContext = `of-entity-${stixDomainObjectOrStixCoreRelationship.id}`;
    } else if (authorId) {
      exportContext = `of-entity-${authorId}`;
    }

    return (
      <UserContext.Consumer>
        {({ helper }) => (
          <ListLines
            sortBy={sortBy}
            orderAsc={orderAsc}
            dataColumns={this.buildColumns(helper)}
            handleSort={this.handleSort.bind(this)}
            handleSearch={this.handleSearch.bind(this)}
            handleAddFilter={this.handleAddFilter.bind(this)}
            handleRemoveFilter={this.handleRemoveFilter.bind(this)}
            handleToggleExports={this.handleToggleExports.bind(this)}
            handleChangeView={this.handleChangeView.bind(this)}
            openExports={openExports}
            noPadding={typeof this.props.onChangeOpenExports === 'function'}
            exportEntityType="Report"
            exportContext={exportContext}
            keyword={searchTerm}
            filters={filters}
            paginationOptions={paginationOptions}
            numberOfElements={numberOfElements}
            disableCards={true}
            enableGraph={true}
            availableFilterKeys={[
              'report_types',
              'container_type',
              'confidence_gt',
              'x_opencti_workflow_id',
              'labelledBy',
              'createdBy',
              'markedBy',
              'created_start_date',
              'created_end_date',
            ]}
          >
            <QueryRenderer
              query={stixCoreObjectOrStixCoreRelationshipContainersLinesQuery}
              variables={{ count: 25, ...paginationOptions }}
              render={({ props }) => (
                <StixCoreObjectOrStixCoreRelationshipContainersLines
                  data={props}
                  paginationOptions={paginationOptions}
                  dataColumns={this.buildColumns(helper)}
                  initialLoading={props === null}
                  onLabelClick={this.handleAddFilter.bind(this)}
                  setNumberOfElements={this.setNumberOfElements.bind(this)}
                />
              )}
            />
          </ListLines>
        )}
      </UserContext.Consumer>
    );
  }

  renderGraph(paginationOptions) {
    const { stixDomainObjectOrStixCoreRelationship, classes, t } = this.props;
    const { searchTerm, filters } = this.state;
    const availableFilterKeys = [
      'labelledBy',
      'createdBy',
      'markedBy',
      'created_start_date',
      'created_end_date',
      'container_type',
      'report_types',
    ];
    return (
      <div>
        <div className={classes.parameters}>
          {typeof handleSearch === 'function' && (
            <div style={{ float: 'left', marginRight: 20 }}>
              <SearchInput
                variant="small"
                onSubmit={this.handleSearch.bind(this)}
                keyword={searchTerm}
              />
            </div>
          )}
          <Filters
            availableFilterKeys={availableFilterKeys}
            handleAddFilter={this.handleAddFilter.bind(this)}
          />
          <div className={classes.filters}>
            {map((currentFilter) => {
              const label = `${truncate(t(`filter_${currentFilter[0]}`), 20)}`;
              const values = (
                <span>
                  {map(
                    (n) => (
                      <span key={n.value}>
                        {n.value && n.value.length > 0
                          ? truncate(n.value, 15)
                          : t('No label')}{' '}
                        {last(currentFilter[1]).value !== n.value && (
                          <code>OR</code>
                        )}
                      </span>
                    ),
                    currentFilter[1],
                  )}
                </span>
              );
              return (
                <span>
                  <Chip
                    key={currentFilter[0]}
                    classes={{ root: classes.filter }}
                    label={
                      <div>
                        <strong>{label}</strong>: {values}
                      </div>
                    }
                    onDelete={this.handleRemoveFilter.bind(
                      this,
                      currentFilter[0],
                    )}
                  />
                  {last(toPairs(filters))[0] !== currentFilter[0] && (
                    <Chip
                      classes={{ root: classes.operator }}
                      label={t('AND')}
                    />
                  )}
                </span>
              );
            }, toPairs(filters))}
          </div>
          <div className="clearfix" />
        </div>
        <QueryRenderer
          query={stixCoreObjectOrStixCoreRelationshipContainersGraphQuery}
          variables={{
            id: stixDomainObjectOrStixCoreRelationship.id,
            types: [
              'Threat-Actor',
              'Intrusion-Set',
              'Campaign',
              'Incident',
              'Malware',
              'Tool',
              'Vulnerability',
              'Attack-Pattern',
              'Sector',
              'Organization',
              'Individual',
              'Region',
              'Country',
              'City',
              'uses',
              'targets',
              'attributed-to',
              'located-at',
              'part-of',
              'belongs-to',
              'related-to',
            ],
            filters: paginationOptions.filters,
            search: searchTerm,
          }}
          render={({ props }) => {
            if (props) {
              return (
                <StixCoreObjectOrStixCoreRelationshipContainersGraph
                  params={this.params}
                  saveViewParameters={this.saveViewParameters.bind(this)}
                  stixDomainObjectOrStixCoreRelationship={
                    stixDomainObjectOrStixCoreRelationship
                  }
                  data={props}
                  handleChangeView={this.handleChangeView.bind(this)}
                />
              );
            }
            return (
              <div>
                <StixCoreObjectOrStixCoreRelationshipContainersGraphBar
                  disabled={true}
                />
                <Loader />
              </div>
            );
          }}
        />
      </div>
    );
  }

  render() {
    const {
      classes,
      match: {
        params: { reportType },
      },
      stixDomainObjectOrStixCoreRelationship,
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
    if (
      stixDomainObjectOrStixCoreRelationship
      && stixDomainObjectOrStixCoreRelationship.id
    ) {
      finalFilters.push({
        key: 'objectContains',
        values: [stixDomainObjectOrStixCoreRelationship.id],
      });
    }
    const paginationOptions = {
      filters: finalFilters,
      search: searchTerm,
      orderBy: sortBy,
      orderMode: orderAsc ? 'asc' : 'desc',
    };
    return (
      <div
        className={
          view === 'lines' ? classes.container : classes.containerGraph
        }
      >
        {view === 'lines' ? this.renderLines(paginationOptions) : ''}
        {view === 'graph' ? this.renderGraph(paginationOptions) : ''}
      </div>
    );
  }
}

StixCoreObjectOrStixCoreRelationshipContainers.propTypes = {
  stixDomainObjectOrStixCoreRelationship: PropTypes.object,
  authorId: PropTypes.string,
  t: PropTypes.func,
  match: PropTypes.object,
  history: PropTypes.object,
  location: PropTypes.object,
  onChangeOpenExports: PropTypes.func,
  viewAs: PropTypes.string,
};

export default R.compose(
  inject18n,
  withRouter,
  withStyles(styles),
)(StixCoreObjectOrStixCoreRelationshipContainers);
