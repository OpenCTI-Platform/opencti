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
import ContainerStixCyberObservablesLines, {
  containerStixCyberObservablesLinesQuery,
} from './ContainerStixCyberObservablesLines';
import {
  buildViewParamsFromUrlAndStorage,
  saveViewParameters,
} from '../../../../utils/ListParameters';
import inject18n from '../../../../components/i18n';
import ContainerAddObservables from '../../analysis/containers/ContainerAddObservables';
import StixCyberObservablesRightBar from '../../signatures/stix_cyber_observables/StixCyberObservablesRightBar';
import Security, { KNOWLEDGE_KNUPDATE } from '../../../../utils/Security';

const styles = () => ({
  container: {
    margin: 0,
    padding: '0 250px 0 0',
  },
});

class ContainerStixCyberObservablesComponent extends Component {
  constructor(props) {
    super(props);
    const params = buildViewParamsFromUrlAndStorage(
      props.history,
      props.location,
      `view-container-${props.container.id}-stix-observables`,
    );
    this.state = {
      sortBy: propOr('created_at', 'sortBy', params),
      orderAsc: propOr(false, 'orderAsc', params),
      searchTerm: propOr('', 'searchTerm', params),
      types: [],
      openExports: false,
      numberOfElements: { number: 0, symbol: '' },
    };
  }

  saveView() {
    saveViewParameters(
      this.props.history,
      this.props.location,
      `view-container-${this.props.container.id}-stix-observables`,
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

  setNumberOfElements(numberOfElements) {
    this.setState({ numberOfElements });
  }

  render() {
    const { container, classes } = this.props;
    const {
      sortBy,
      orderAsc,
      searchTerm,
      types,
      openExports,
      numberOfElements,
    } = this.state;
    const dataColumns = {
      entity_type: {
        label: 'Type',
        width: '15%',
        isSortable: true,
      },
      observable_value: {
        label: 'Value',
        width: '35%',
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
      types,
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
          secondaryAction={true}
          numberOfElements={numberOfElements}
        >
          <QueryRenderer
            query={containerStixCyberObservablesLinesQuery}
            variables={{ id: container.id, count: 25, ...paginationOptions }}
            render={({ props }) => (
              <ContainerStixCyberObservablesLines
                container={props ? props.container : null}
                paginationOptions={paginationOptions}
                dataColumns={dataColumns}
                initialLoading={props === null}
                setNumberOfElements={this.setNumberOfElements.bind(this)}
              />
            )}
          />
        </ListLines>
        <Security needs={[KNOWLEDGE_KNUPDATE]}>
          <ContainerAddObservables
            containerId={container.id}
            paginationOptions={paginationOptions}
          />
        </Security>
        <StixCyberObservablesRightBar
          types={types}
          handleToggle={this.handleToggle.bind(this)}
          openExports={openExports}
        />
      </div>
    );
  }
}

ContainerStixCyberObservablesComponent.propTypes = {
  container: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  fd: PropTypes.func,
  history: PropTypes.object,
};

const ContainerStixCyberObservables = createFragmentContainer(
  ContainerStixCyberObservablesComponent,
  {
    container: graphql`
      fragment ContainerStixCyberObservables_container on Container {
        id
        ...ContainerHeader_container
      }
    `,
  },
);

export default compose(
  inject18n,
  withStyles(styles),
)(ContainerStixCyberObservables);
