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
import CurationStixDomainEntitiesLines, {
  curationStixDomainEntitiesLinesQuery,
} from './curation/CurationStixDomainEntitiesLines';
import inject18n from '../../../components/i18n';
import {
  buildViewParamsFromUrlAndStorage,
  convertFilters,
  saveViewParameters,
} from '../../../utils/ListParameters';
import StixDomainEntitiesRightBar from '../common/stix_domain_entities/StixDomainEntitiesRightBar';

const styles = () => ({
  container: {
    paddingRight: 250,
  },
});

class StixObservables extends Component {
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
      stixDomainEntitiesTypes: propOr([], 'stixDomainEntitiesTypes', params),
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
    if (this.state.stixDomainEntitiesTypes.includes(type)) {
      this.setState(
        {
          stixDomainEntitiesTypes: filter(
            (t) => t !== type,
            this.state.stixDomainEntitiesTypes,
          ),
        },
        () => this.saveView(),
      );
    } else {
      this.setState(
        {
          stixDomainEntitiesTypes: append(
            type,
            this.state.stixDomainEntitiesTypes,
          ),
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
      tags: {
        label: 'Tags',
        width: '20%',
        isSortable: false,
      },
      created_at: {
        label: 'Creation date',
        width: '15%',
        isSortable: true,
      },
      markingDefinitions: {
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
            'tags',
            'markingDefinitions',
            'created_start_date',
            'created_end_date',
            'createdBy',
          ]}
        >
          <QueryRenderer
            query={curationStixDomainEntitiesLinesQuery}
            variables={{ count: 25, ...paginationOptions }}
            render={({ props }) => (
              <CurationStixDomainEntitiesLines
                data={props}
                paginationOptions={paginationOptions}
                dataColumns={dataColumns}
                initialLoading={props === null}
                onTagClick={this.handleAddFilter.bind(this)}
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
      view,
      stixDomainEntitiesTypes,
      sortBy,
      orderAsc,
      searchTerm,
      filters,
    } = this.state;
    const finalFilters = convertFilters(filters);
    const paginationOptions = {
      types:
        stixDomainEntitiesTypes.length > 0 ? stixDomainEntitiesTypes : null,
      search: searchTerm,
      filters: finalFilters,
      orderBy: sortBy,
      orderMode: orderAsc ? 'asc' : 'desc',
    };
    return (
      <div className={classes.container}>
        {view === 'lines' ? this.renderLines(paginationOptions) : ''}
        <StixDomainEntitiesRightBar
          stixDomainEntitiesTypes={stixDomainEntitiesTypes}
          handleToggleStixDomainEntityType={this.handleToggle.bind(this)}
        />
      </div>
    );
  }
}

StixObservables.propTypes = {
  classes: PropTypes.object,
  t: PropTypes.func,
  history: PropTypes.object,
  location: PropTypes.object,
};

export default compose(
  inject18n,
  withRouter,
  withStyles(styles),
)(StixObservables);
