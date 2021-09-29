import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import {
  append, compose, filter, propOr,
} from 'ramda';
import graphql from 'babel-plugin-relay/macro';
import { createFragmentContainer } from 'react-relay';
import { withStyles } from '@material-ui/core';
import * as R from 'ramda';
import { QueryRenderer } from '../../../../relay/environment';
import ListLines from '../../../../components/list_lines/ListLines';
import ContainerStixDomainObjectsLines, {
  containerStixDomainObjectsLinesQuery,
} from './ContainerStixDomainObjectsLines';
import StixDomainObjectsRightBar from '../stix_domain_objects/StixDomainObjectsRightBar';
import {
  buildViewParamsFromUrlAndStorage,
  saveViewParameters,
} from '../../../../utils/ListParameters';
import inject18n from '../../../../components/i18n';
import { defaultValue } from '../../../../utils/Graph';
import ToolBar from '../../data/ToolBar';

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
      types: propOr([], 'types', params),
      openExports: false,
      numberOfElements: { number: 0, symbol: '' },
      selectedElements: null,
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

  handleToggleSelectAll() {
    this.setState({ selectAll: !this.state.selectAll, selectedElements: null });
  }

  handleClearSelectedElements() {
    this.setState({ selectAll: false, selectedElements: null });
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
      selectAll,
      types,
    } = this.state;
    let numberOfSelectedElements = Object.keys(selectedElements || {}).length;
    if (selectAll) {
      numberOfSelectedElements = numberOfElements.original;
    }
    const dataColumns = {
      entity_type: {
        label: 'Type',
        width: '15%',
        isSortable: true,
      },
      name: {
        label: 'Name',
        width: '40%',
        isSortable: true,
      },
      createdBy: {
        label: 'Creator',
        width: '15%',
        isSortable: true,
      },
      created_at: {
        label: 'Creation date',
        width: '15%',
        isSortable: true,
      },
      objectMarking: {
        label: 'Marking',
        isSortable: true,
      },
    };
    const paginationOptions = {
      types: types.length > 0 ? types : ['Stix-Domain-Object'],
      filters: null,
      search: searchTerm,
      orderBy: sortBy,
      orderMode: orderAsc ? 'asc' : 'desc',
    };
    const filters = [{ key: 'containedBy', values: [container.id] }];
    if (types.length > 0) {
      filters.push({ key: 'entity_type', values: types });
    }
    const exportPaginationOptions = {
      filters,
      orderBy: sortBy,
      orderMode: orderAsc ? 'asc' : 'desc',
      search: searchTerm,
    };
    const finalFilters = {
      entity_type:
        types.length > 0
          ? R.map((n) => ({ id: n, value: n }), types)
          : [{ id: 'Stix-Domain-Object', value: 'Stix-Domain-Object' }],
      containedBy: [{ id: container.id, value: defaultValue(container) }],
    };
    return (
      <div className={classes.container}>
        <ListLines
          sortBy={sortBy}
          orderAsc={orderAsc}
          dataColumns={dataColumns}
          handleSort={this.handleSort.bind(this)}
          handleSearch={this.handleSearch.bind(this)}
          handleToggleExports={this.handleToggleExports.bind(this)}
          handleToggleSelectAll={this.handleToggleSelectAll.bind(this)}
          selectAll={selectAll}
          iconExtension={true}
          exportEntityType="Stix-Domain-Object"
          openExports={openExports}
          exportContext={`of-container-${container.id}`}
          keyword={searchTerm}
          secondaryAction={true}
          numberOfElements={numberOfElements}
          paginationOptions={exportPaginationOptions}
        >
          <QueryRenderer
            query={containerStixDomainObjectsLinesQuery}
            variables={{ id: container.id, count: 25, ...paginationOptions }}
            render={({ props }) => (
              <ContainerStixDomainObjectsLines
                container={props ? props.container : null}
                paginationOptions={paginationOptions}
                dataColumns={dataColumns}
                initialLoading={props === null}
                setNumberOfElements={this.setNumberOfElements.bind(this)}
                onTypesChange={this.handleToggle.bind(this)}
                openExports={openExports}
                selectedElements={selectedElements}
                onToggleEntity={this.handleToggleSelectEntity.bind(this)}
                selectAll={selectAll}
              />
            )}
          />
        </ListLines>
        <ToolBar
          selectedElements={selectedElements}
          numberOfSelectedElements={numberOfSelectedElements}
          selectAll={selectAll}
          filters={finalFilters}
          handleClearSelectedElements={this.handleClearSelectedElements.bind(
            this,
          )}
          withPaddingRight={true}
        />
        <StixDomainObjectsRightBar
          types={types}
          handleToggle={this.handleToggle.bind(this)}
          handleClear={this.handleClear.bind(this)}
          openExports={openExports}
        />
      </div>
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
