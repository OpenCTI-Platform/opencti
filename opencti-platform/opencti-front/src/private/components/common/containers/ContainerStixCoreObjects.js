import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import {
  append, compose, filter, propOr,
} from 'ramda';
import graphql from 'babel-plugin-relay/macro';
import { createFragmentContainer } from 'react-relay';
import { withStyles } from '@material-ui/core';
import { QueryRenderer } from '../../../../relay/environment';
import ContainerHeader from './ContainerHeader';
import ListLines from '../../../../components/list_lines/ListLines';
import ContainerStixCoreObjectsLines, {
  containerStixCoreObjectsLinesQuery,
} from './ContainerStixCoreObjectsLines';
import StixDomainObjectsRightBar from '../stix_domain_objects/StixDomainObjectsRightBar';
import {
  buildViewParamsFromUrlAndStorage,
  saveViewParameters,
} from '../../../../utils/ListParameters';
import inject18n from '../../../../components/i18n';

const styles = () => ({
  container: {
    margin: 0,
    padding: '0 260px 90px 0',
  },
});

class ContainerStixCoreObjectsComponent extends Component {
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
      stixCoreObjectsTypes: propOr([], 'stixCoreObjectsTypes', params),
      openExports: false,
      numberOfElements: { number: 0, symbol: '' },
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

  handleToggleStixCoreObjectType(type) {
    if (this.state.stixCoreObjectsTypes.includes(type)) {
      this.setState(
        {
          stixCoreObjectsTypes: filter(
            (t) => t !== type,
            this.state.stixCoreObjectsTypes,
          ),
        },
        () => this.saveView(),
      );
    } else {
      this.setState(
        {
          stixCoreObjectsTypes: append(type, this.state.stixCoreObjectsTypes),
        },
        () => this.saveView(),
      );
    }
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

  setNumberOfElements(numberOfElements) {
    this.setState({ numberOfElements });
  }

  render() {
    const { container, classes } = this.props;
    const {
      sortBy,
      orderAsc,
      searchTerm,
      stixCoreObjectsTypes,
      openExports,
      numberOfElements,
    } = this.state;
    const dataColumns = {
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
      createdBy: {
        label: 'Creator',
        width: '15%',
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
    const paginationOptions = {
      types: stixCoreObjectsTypes,
      filters: null,
      search: searchTerm,
      orderBy: sortBy,
      orderMode: orderAsc ? 'asc' : 'desc',
    };
    return (
      <div className={classes.container}>
        <ContainerHeader container={container} />
        <br />
        <ListLines
          sortBy={sortBy}
          orderAsc={orderAsc}
          dataColumns={dataColumns}
          handleSort={this.handleSort.bind(this)}
          handleSearch={this.handleSearch.bind(this)}
          keyword={searchTerm}
          secondaryAction={true}
          numberOfElements={numberOfElements}
        >
          <QueryRenderer
            query={containerStixCoreObjectsLinesQuery}
            variables={{ id: container.id, count: 25, ...paginationOptions }}
            render={({ props }) => (
              <ContainerStixCoreObjectsLines
                container={props ? props.container : null}
                paginationOptions={paginationOptions}
                dataColumns={dataColumns}
                initialLoading={props === null}
                setNumberOfElements={this.setNumberOfElements.bind(this)}
              />
            )}
          />
        </ListLines>
        <StixDomainObjectsRightBar
          stixCoreObjectsTypes={stixCoreObjectsTypes}
          handleToggleStixCoreObjectType={this.handleToggleStixCoreObjectType.bind(
            this,
          )}
          openExports={openExports}
        />
      </div>
    );
  }
}

ContainerStixCoreObjectsComponent.propTypes = {
  container: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  fd: PropTypes.func,
  history: PropTypes.object,
};

const ContainerStixCoreObjects = createFragmentContainer(
  ContainerStixCoreObjectsComponent,
  {
    container: graphql`
      fragment ContainerStixCoreObjects_container on Container {
        id
        ...ContainerHeader_container
      }
    `,
  },
);

export default compose(inject18n, withStyles(styles))(ContainerStixCoreObjects);
