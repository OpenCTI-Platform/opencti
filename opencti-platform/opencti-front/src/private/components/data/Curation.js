import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import {
  compose, append, filter, propOr, assoc, dissoc, omit,
} from 'ramda';
import { withRouter } from 'react-router-dom';
import { withStyles } from '@material-ui/core/styles';
import { QueryRenderer } from '../../../relay/environment';
import ListLines from '../../../components/list_lines/ListLines';
import CurationToolBar from './curation/CurationToolBar';
import CurationStixDomainObjectsLines, {
  curationStixDomainObjectsLinesQuery,
} from './curation/CurationStixDomainObjectsLines';
import inject18n from '../../../components/i18n';
import {
  buildViewParamsFromUrlAndStorage,
  convertFilters,
  saveViewParameters,
} from '../../../utils/ListParameters';
import StixDomainObjectsRightBar from '../common/stix_domain_objects/StixDomainObjectsRightBar';

const styles = () => ({
  container: {
    paddingRight: 250,
  },
});

class StixCyberObservables extends Component {
  constructor(props) {
    super(props);
    const params = buildViewParamsFromUrlAndStorage(
      props.history,
      props.location,
      'view-curation',
    );
    this.state = {
      sortBy: propOr('created_at', 'sortBy', params),
      orderAsc: propOr(false, 'orderAsc', params),
      searchTerm: propOr('', 'searchTerm', params),
      view: propOr('lines', 'view', params),
      filters: {},
      types: propOr([], 'types', params),
      numberOfElements: { number: 0, symbol: '' },
      selectedElements: {},
    };
  }

  saveView() {
    saveViewParameters(
      this.props.history,
      this.props.location,
      'view-curation',
      dissoc('filters', this.state),
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

  handleResetSelectedElements() {
    this.setState({ selectedElements: {} });
  }

  handleToggle(type) {
    if (this.state.types.includes(type)) {
      this.setState(
        {
          types: filter((t) => t !== type, this.state.types),
        },
        () => this.saveView(),
      );
    } else {
      this.setState(
        {
          types: append(type, this.state.types),
        },
        () => this.saveView(),
      );
    }
  }

  handleAddFilter(key, id, value, event = null) {
    if (event) {
      event.stopPropagation();
      event.preventDefault();
    }
    this.setState({
      filters: assoc(key, [{ id, value }], this.state.filters),
    });
  }

  handleRemoveFilter(key) {
    this.setState({ filters: dissoc(key, this.state.filters) });
  }

  setNumberOfElements(numberOfElements) {
    this.setState({ numberOfElements });
  }

  handleToggleSelectEntity(entity) {
    if (entity.id in this.state.selectedElements) {
      this.setState({
        selectedElements: omit([entity.id], this.state.selectedElements),
      });
    } else {
      this.setState({
        selectedElements: assoc(entity.id, entity, this.state.selectedElements),
      });
    }
  }

  renderLines(paginationOptions) {
    const {
      sortBy,
      orderAsc,
      searchTerm,
      filters,
      numberOfElements,
      selectedElements,
    } = this.state;
    const dataColumns = {
      entity_type: {
        label: 'Type',
        width: '10%',
        isSortable: true,
      },
      name: {
        label: 'Name',
        width: '25%',
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
      created_at: {
        label: 'Creation date',
        width: '15%',
        isSortable: true,
      },
      objectMarking: {
        label: 'Marking',
        isSortable: false,
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
          handleChangeView={this.handleChangeView.bind(this)}
          disableCards={true}
          keyword={searchTerm}
          filters={filters}
          paginationOptions={paginationOptions}
          numberOfElements={numberOfElements}
          availableFilterKeys={[
            'labels',
            'markingDefinitions',
            'created_start_date',
            'created_end_date',
            'createdBy',
          ]}
        >
          <QueryRenderer
            query={curationStixDomainObjectsLinesQuery}
            variables={{ count: 25, ...paginationOptions }}
            render={({ props }) => (
              <CurationStixDomainObjectsLines
                data={props}
                paginationOptions={paginationOptions}
                dataColumns={dataColumns}
                initialLoading={props === null}
                onLabelClick={this.handleAddFilter.bind(this)}
                selectedElements={selectedElements}
                onToggleEntity={this.handleToggleSelectEntity.bind(this)}
                setNumberOfElements={this.setNumberOfElements.bind(this)}
              />
            )}
          />
        </ListLines>
        <CurationToolBar
          paginationOptions={paginationOptions}
          selectedElements={selectedElements}
          handleResetSelectedElements={this.handleResetSelectedElements.bind(
            this,
          )}
        />
      </div>
    );
  }

  render() {
    const { classes } = this.props;
    const {
      view, types, sortBy, orderAsc, searchTerm, filters,
    } = this.state;
    const finalFilters = convertFilters(filters);
    const paginationOptions = {
      types: types.length > 0 ? types : null,
      search: searchTerm,
      filters: finalFilters,
      orderBy: sortBy,
      orderMode: orderAsc ? 'asc' : 'desc',
    };
    return (
      <div className={classes.container}>
        {view === 'lines' ? this.renderLines(paginationOptions) : ''}
        <StixDomainObjectsRightBar
          types={types}
          handleToggle={this.handleToggle.bind(this)}
        />
      </div>
    );
  }
}

StixCyberObservables.propTypes = {
  classes: PropTypes.object,
  t: PropTypes.func,
  history: PropTypes.object,
  location: PropTypes.object,
};

export default compose(
  inject18n,
  withRouter,
  withStyles(styles),
)(StixCyberObservables);
