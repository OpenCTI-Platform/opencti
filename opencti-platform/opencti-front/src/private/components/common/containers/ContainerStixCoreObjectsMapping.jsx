import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { graphql, createFragmentContainer } from 'react-relay';
import withStyles from '@mui/styles/withStyles';
import * as R from 'ramda';
import { QueryRenderer } from '../../../../relay/environment';
import ListLines from '../../../../components/list_lines/ListLines';
import ContainerStixCoreObjectsMappingLines, {
  containerStixCoreObjectsMappingLinesQuery,
} from './ContainerStixCoreObjectsMappingLines';
import { convertFilters } from '../../../../utils/ListParameters';
import inject18n from '../../../../components/i18n';
import { UserContext } from '../../../../utils/hooks/useAuth';
import { isUniqFilter } from '../../../../utils/filters/filtersUtils';

const styles = () => ({
  container: {
    margin: 0,
    padding: '15px 0 0 0',
  },
});

class ContainerStixCoreObjectsComponent extends Component {
  constructor(props) {
    super(props);
    this.state = {
      sortBy: 'name',
      orderAsc: false,
      searchTerm: '',
      filters: {},
      numberOfElements: { number: 0, symbol: '' },
    };
  }

  handleSearch(value) {
    this.setState({ searchTerm: value });
  }

  handleSort(field, orderAsc) {
    this.setState({ sortBy: field, orderAsc });
  }

  setNumberOfElements(numberOfElements) {
    this.setState({ numberOfElements });
  }

  handleAddFilter(key, id, value, event = null) {
    if (event) {
      event.stopPropagation();
      event.preventDefault();
    }
    if (this.state.filters[key] && this.state.filters[key].length > 0) {
      this.setState({
        filters: {
          ...this.state.filters,
          [key]: isUniqFilter(key)
            ? [{ id, value }]
            : R.uniqBy(R.prop('id'), [
              { id, value },
              ...this.state.filters[key],
            ]),
        },
      });
    } else {
      this.setState({
        filters: { ...this.state.filters, [key]: [{ id, value }] },
      });
    }
  }

  handleRemoveFilter(key) {
    this.setState({ filters: R.dissoc(key, this.state.filters) });
  }

  // eslint-disable-next-line class-methods-use-this
  buildColumns(platformModuleHelpers) {
    const isRuntimeSort = platformModuleHelpers.isRuntimeFieldEnable();
    return {
      entity_type: {
        label: 'Type',
        width: '15%',
        isSortable: true,
      },
      value: {
        label: 'Value',
        width: '35%',
        isSortable: false,
      },
      createdBy: {
        label: 'Author',
        width: '15%',
        isSortable: isRuntimeSort,
      },
      created_at: {
        label: 'Creation',
        width: '12%',
        isSortable: true,
      },
      objectMarking: {
        label: 'Marking',
        width: '10%',
        isSortable: isRuntimeSort,
      },
    };
  }

  render() {
    const { container, classes, height } = this.props;
    const { sortBy, orderAsc, searchTerm, numberOfElements, filters } = this.state;
    const finalFilters = convertFilters(filters);
    const paginationOptions = {
      search: searchTerm,
      filters: finalFilters,
      orderBy: sortBy,
      orderMode: orderAsc ? 'asc' : 'desc',
    };
    return (
      <UserContext.Consumer>
        {({ platformModuleHelpers }) => (
          <div className={classes.container}>
            <ListLines
              sortBy={sortBy}
              orderAsc={orderAsc}
              dataColumns={this.buildColumns(platformModuleHelpers)}
              handleSort={this.handleSort.bind(this)}
              handleSearch={this.handleSearch.bind(this)}
              handleAddFilter={this.handleAddFilter.bind(this)}
              handleRemoveFilter={this.handleRemoveFilter.bind(this)}
              iconExtension={false}
              filters={filters}
              availableFilterKeys={[
                'entity_type',
                'labelledBy',
                'markedBy',
                'created_at_start_date',
                'created_at_end_date',
                'createdBy',
              ]}
              keyword={searchTerm}
              secondaryAction={true}
              numberOfElements={numberOfElements}
              noPadding={true}
            >
              <QueryRenderer
                query={containerStixCoreObjectsMappingLinesQuery}
                variables={{
                  id: container.id,
                  count: 25,
                  ...paginationOptions,
                }}
                render={({ props }) => (
                  <ContainerStixCoreObjectsMappingLines
                    container={props ? props.container : null}
                    paginationOptions={paginationOptions}
                    searchTerm={searchTerm}
                    dataColumns={this.buildColumns(platformModuleHelpers)}
                    initialLoading={props === null}
                    setNumberOfElements={this.setNumberOfElements.bind(this)}
                    height={height}
                  />
                )}
              />
            </ListLines>
          </div>
        )}
      </UserContext.Consumer>
    );
  }
}

ContainerStixCoreObjectsComponent.propTypes = {
  container: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  fd: PropTypes.func,
  history: PropTypes.object,
  height: PropTypes.number,
};

const ContainerStixCoreObjectsMapping = createFragmentContainer(
  ContainerStixCoreObjectsComponent,
  {
    container: graphql`
      fragment ContainerStixCoreObjectsMapping_container on Container {
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
          name
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
)(ContainerStixCoreObjectsMapping);
