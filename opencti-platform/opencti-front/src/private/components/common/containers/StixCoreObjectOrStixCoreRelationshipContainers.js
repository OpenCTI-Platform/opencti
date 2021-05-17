import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { withRouter } from 'react-router-dom';
import Drawer from '@material-ui/core/Drawer';
import { withStyles } from '@material-ui/core/styles';
import Tooltip from '@material-ui/core/Tooltip';
import IconButton from '@material-ui/core/IconButton';
import { GraphOutline } from 'mdi-material-ui';
import { TableChartOutlined } from '@material-ui/icons';
import * as R from 'ramda';
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
import { isUniqFilter } from '../lists/Filters';

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
    backgroundColor: theme.palette.navBottom.background,
    display: 'flex',
    overflow: 'hidden',
  },
  button: {
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
        props.stixDomainObjectOrStixCoreRelationship.id
          ? `-${props.stixDomainObjectOrStixCoreRelationship.id}`
          : ''
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
        this.props.stixDomainObjectOrStixCoreRelationship.id
          ? `-${this.props.stixDomainObjectOrStixCoreRelationship.id}`
          : ''
      }`,
      this.state,
    );
  }

  saveViewParameters(params) {
    saveViewParameters(
      this.props.history,
      this.props.location,
      `view-containers${
        this.props.stixDomainObjectOrStixCoreRelationship.id
          ? `-${this.props.stixDomainObjectOrStixCoreRelationship.id}`
          : ''
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

    const dataColumns = {
      name: {
        label: 'Title',
        width: '30%',
        isSortable: true,
      },
      createdBy: {
        label: 'Author',
        width: '15%',
        isSortable: false,
      },
      objectLabel: {
        label: 'Labels',
        width: '20%',
        isSortable: false,
      },
      created: {
        label: 'Date',
        width: '15%',
        isSortable: true,
      },
      objectMarking: {
        label: 'Marking',
        width: '15%',
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
        handleAddFilter={this.handleAddFilter.bind(this)}
        handleRemoveFilter={this.handleRemoveFilter.bind(this)}
        handleToggleExports={this.handleToggleExports.bind(this)}
        openExports={openExports}
        noPadding={typeof this.props.onChangeOpenExports === 'function'}
        exportEntityType="Report"
        exportContext={exportContext}
        keyword={searchTerm}
        filters={filters}
        paginationOptions={paginationOptions}
        numberOfElements={numberOfElements}
        availableFilterKeys={[
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
              dataColumns={dataColumns}
              initialLoading={props === null}
              onLabelClick={this.handleAddFilter.bind(this)}
              setNumberOfElements={this.setNumberOfElements.bind(this)}
            />
          )}
        />
      </ListLines>
    );
  }

  renderGraph() {
    const { stixDomainObjectOrStixCoreRelationship } = this.props;
    return (
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
          ],
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
                handleChangeView={this.handleChangeView.bind(this)}
              />
              <Loader />
            </div>
          );
        }}
      />
    );
  }

  render() {
    const {
      classes,
      t,
      match: {
        params: { reportType },
      },
      stixDomainObjectOrStixCoreRelationship,
      authorId,
    } = this.props;
    const {
      view, sortBy, orderAsc, searchTerm, filters,
    } = this.state;
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
        {!authorId && view === 'lines' && (
          <Drawer
            anchor="bottom"
            variant="permanent"
            classes={{ paper: classes.bottomNav }}
          >
            <div
              style={{
                height: 54,
                verticalAlign: 'top',
                transition: 'height 0.2s linear',
              }}
            >
              <div
                style={{
                  verticalAlign: 'top',
                  width: '100%',
                  height: 54,
                  paddingTop: 3,
                }}
              >
                <div
                  style={{
                    float: 'left',
                    marginLeft: 190,
                    height: '100%',
                    display: 'flex',
                  }}
                >
                  <Tooltip title={t('Lines view')}>
                    <IconButton
                      color="secondary"
                      onClick={this.handleChangeView.bind(this, 'lines')}
                    >
                      <TableChartOutlined />
                    </IconButton>
                  </Tooltip>
                  <Tooltip title={t('Graph view')}>
                    <IconButton
                      color="primary"
                      onClick={this.handleChangeView.bind(this, 'graph')}
                    >
                      <GraphOutline />
                    </IconButton>
                  </Tooltip>
                </div>
              </div>
            </div>
          </Drawer>
        )}
        {view === 'lines' ? this.renderLines(paginationOptions) : ''}
        {view === 'graph' ? this.renderGraph() : ''}
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
