import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { append, compose, filter, propOr } from 'ramda';
import { graphql, createFragmentContainer } from 'react-relay';
import withStyles from '@mui/styles/withStyles';
import * as R from 'ramda';
import { QueryRenderer } from '../../../../relay/environment';
import ListLines from '../../../../components/list_lines/ListLines';
import ContainerStixDomainObjectsLines, {
  containerStixDomainObjectsLinesQuery,
} from './ContainerStixDomainObjectsLines';
import StixDomainObjectsRightBar from '../stix_domain_objects/StixDomainObjectsRightBar';
import {
  buildViewParamsFromUrlAndStorage,
  convertFilters,
  saveViewParameters,
} from '../../../../utils/ListParameters';
import inject18n from '../../../../components/i18n';
import { defaultValue } from '../../../../utils/Graph';
import ToolBar from '../../data/ToolBar';
import { UserContext } from '../../../../utils/hooks/useAuth';
import { isUniqFilter } from '../../../../utils/filters/filtersUtils';
import ExportContextProvider from '../../../../utils/ExportContextProvider';

const styles = () => ({
  container: {
    margin: '20px 0 0 0',
    padding: '0 260px 90px 0',
  },
});

class ContainerStixDomainObjectsComponent extends Component {
  constructor(props) {
    super(props);
    const params = buildViewParamsFromUrlAndStorage(
      props.history,
      props.location,
      `view-container-${props.container.id}-stix-domain-entities`,
    );
    this.state = {
      sortBy: propOr('name', 'sortBy', params),
      orderAsc: propOr(false, 'orderAsc', params),
      searchTerm: propOr('', 'searchTerm', params),
      filters: R.propOr({}, 'filters', params),
      types: propOr([], 'types', params),
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
      `view-container-${this.props.container.id}-stix-domain-entities`,
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
    this.setState({ openExports: !this.state.openExports });
  }

  handleToggle(type) {
    if (this.state.types.includes(type)) {
      this.setState(
        { types: filter((t) => t !== type, this.state.types) },
        () => this.saveView(),
      );
    } else {
      this.setState({ types: append(type, this.state.types) }, () => this.saveView());
    }
  }

  handleClear() {
    this.setState({ types: [] }, () => this.saveView());
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
      const newDeSelectedElements = { ...deSelectedElements, [entity.id]: entity };
      this.setState({
        deSelectedElements: newDeSelectedElements,
      });
    } else {
      const newSelectedElements = { ...selectedElements, [entity.id]: entity };
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

  handleAddFilter(key, id, value, event = null) {
    if (event) {
      event.stopPropagation();
      event.preventDefault();
    }
    if (this.state.filters[key] && this.state.filters[key].length > 0) {
      this.setState(
        {
          filters: { ...this.state.filters,
            [key]: isUniqFilter(key)
              ? [{ id, value }]
              : R.uniqBy(R.prop('id'), [
                { id, value },
                ...this.state.filters[key],
              ]) },
        },
        () => this.saveView(),
      );
    } else {
      this.setState(
        {
          filters: { ...this.state.filters, [key]: [{ id, value }] },
        },
        () => this.saveView(),
      );
    }
  }

  handleRemoveFilter(key) {
    this.setState({ filters: R.dissoc(key, this.state.filters) }, () => this.saveView());
  }

  handleClearSelectedElements() {
    this.setState({
      selectAll: false,
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
        width: '15%',
        isSortable: true,
      },
      name: {
        label: 'Name',
        width: '30%',
        isSortable: true,
      },
      objectLabel: {
        label: 'Labels',
        width: '20%',
        isSortable: false,
      },
      createdBy: {
        label: 'Creator',
        width: '15%',
        isSortable: isRuntimeSort,
      },
      created_at: {
        label: 'Creation date',
        width: '10%',
        isSortable: true,
      },
      objectMarking: {
        label: 'Marking',
        isSortable: isRuntimeSort,
      },
    };
  }

  render() {
    const { container, classes } = this.props;
    const {
      sortBy,
      orderAsc,
      searchTerm,
      openExports,
      numberOfElements,
      selectedElements,
      deSelectedElements,
      selectAll,
      types,
      filters,
    } = this.state;
    let numberOfSelectedElements = Object.keys(selectedElements || {}).length;
    if (selectAll) {
      numberOfSelectedElements = numberOfElements.original
        - Object.keys(deSelectedElements || {}).length;
    }
    const finalFilters = convertFilters(filters);
    const paginationOptions = {
      types: types.length > 0 ? types : ['Stix-Domain-Object'],
      search: searchTerm,
      filters: finalFilters,
      orderBy: sortBy,
      orderMode: orderAsc ? 'asc' : 'desc',
    };
    const exportFilters = {
      containedBy: [{ id: container.id, value: defaultValue(container) }],
      entity_type:
        types.length > 0 ? R.map((n) => ({ id: n, value: n }), types) : [],
      ...filters,
    };
    const exportFinalFilters = convertFilters(exportFilters);
    const exportPaginationOptions = {
      filters: exportFinalFilters,
      orderBy: sortBy,
      orderMode: orderAsc ? 'asc' : 'desc',
      search: searchTerm,
    };
    const backgroundTaskFilters = {
      containedBy: [{ id: container.id, value: defaultValue(container) }],
      entity_type:
        types.length > 0
          ? R.map((n) => ({ id: n, value: n }), types)
          : [{ id: 'Stix-Domain-Object', value: 'Stix-Domain-Object' }],
      ...filters,
    };
    return (
      <UserContext.Consumer>
        {({ helper }) => (
          <ExportContextProvider>
          <div className={classes.container}>
            <ListLines
              sortBy={sortBy}
              orderAsc={orderAsc}
              dataColumns={this.buildColumns(helper)}
              handleSort={this.handleSort.bind(this)}
              handleSearch={this.handleSearch.bind(this)}
              handleAddFilter={this.handleAddFilter.bind(this)}
              handleRemoveFilter={this.handleRemoveFilter.bind(this)}
              handleToggleExports={this.handleToggleExports.bind(this)}
              handleToggleSelectAll={this.handleToggleSelectAll.bind(this)}
              selectAll={selectAll}
              iconExtension={true}
              exportEntityType="Stix-Domain-Object"
              openExports={openExports}
              exportContext={`of-container-${container.id}`}
              filters={filters}
              availableFilterKeys={[
                'labelledBy',
                'markedBy',
                'created_at_start_date',
                'created_at_end_date',
                'createdBy',
              ]}
              keyword={searchTerm}
              secondaryAction={true}
              numberOfElements={numberOfElements}
              paginationOptions={exportPaginationOptions}
            >
              <QueryRenderer
                query={containerStixDomainObjectsLinesQuery}
                variables={{
                  id: container.id,
                  count: 25,
                  ...paginationOptions,
                }}
                render={({ props }) => (
                  <ContainerStixDomainObjectsLines
                    container={props ? props.container : null}
                    paginationOptions={paginationOptions}
                    dataColumns={this.buildColumns(helper)}
                    initialLoading={props === null}
                    setNumberOfElements={this.setNumberOfElements.bind(this)}
                    onTypesChange={this.handleToggle.bind(this)}
                    openExports={openExports}
                    selectedElements={selectedElements}
                    deSelectedElements={deSelectedElements}
                    onToggleEntity={this.handleToggleSelectEntity.bind(this)}
                    selectAll={selectAll}
                  />
                )}
              />
            </ListLines>
            <ToolBar
              selectedElements={selectedElements}
              deSelectedElements={deSelectedElements}
              numberOfSelectedElements={numberOfSelectedElements}
              selectAll={selectAll}
              filters={backgroundTaskFilters}
              search={searchTerm}
              handleClearSelectedElements={this.handleClearSelectedElements.bind(
                this,
              )}
              variant="large"
              container={container}
            />
            <StixDomainObjectsRightBar
              types={types}
              handleToggle={this.handleToggle.bind(this)}
              handleClear={this.handleClear.bind(this)}
              openExports={openExports}
            />
          </div>
          </ExportContextProvider>
        )}
      </UserContext.Consumer>
    );
  }
}

ContainerStixDomainObjectsComponent.propTypes = {
  container: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  fd: PropTypes.func,
  history: PropTypes.object,
};

const ContainerStixDomainObjects = createFragmentContainer(
  ContainerStixDomainObjectsComponent,
  {
    container: graphql`
      fragment ContainerStixDomainObjects_container on Container {
        id
        ... on Report {
          name
        }
        ... on Grouping {
          name
        }        
        ... on Note {
          attribute_abstract
          content
        }
        ... on Opinion {
          opinion
        }
        ... on ObservedData {
          first_observed
          last_observed
        }
        ...ContainerHeader_container
      }
    `,
  },
);

export default compose(
  inject18n,
  withStyles(styles),
)(ContainerStixDomainObjects);
