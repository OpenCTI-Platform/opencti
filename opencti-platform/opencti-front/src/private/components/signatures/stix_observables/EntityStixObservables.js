import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose, filter, append } from 'ramda';
import { QueryRenderer } from '../../../../relay/environment';
import inject18n from '../../../../components/i18n';
import ListLines from '../../../../components/list_lines/ListLines';
import EntityStixObservablesLines, {
  entityStixObservablesLinesQuery,
} from './EntityStixObservablesLines';
import StixObservablesRightBar from './StixObservablesRightBar';
import StixRelationCreationFromEntity from '../../common/stix_relations/StixRelationCreationFromEntity';

class EntityStixObservables extends Component {
  constructor(props) {
    super(props);
    this.state = {
      sortBy: null,
      orderAsc: false,
      targetEntityTypes: ['Stix-Observable'],
      view: 'lines',
    };
  }

  handleSort(field, orderAsc) {
    this.setState({ sortBy: field, orderAsc });
  }

  handleToggle(type) {
    if (this.state.targetEntityTypes.includes(type)) {
      this.setState({
        targetEntityTypes:
          filter((t) => t !== type, this.state.targetEntityTypes).length === 0
            ? ['Stix-Observable']
            : filter((t) => t !== type, this.state.targetEntityTypes),
      });
    } else {
      this.setState({
        targetEntityTypes: append(
          type,
          filter((t) => t !== 'Stix-Observable', this.state.targetEntityTypes),
        ),
      });
    }
  }

  renderLines(paginationOptions) {
    const { sortBy, orderAsc } = this.state;
    const { entityLink } = this.props;
    const dataColumns = {
      entity_type: {
        label: 'Type',
        width: '10%',
        isSortable: false,
      },
      observable_value: {
        label: 'Value',
        width: '30%',
        isSortable: false,
      },
      first_seen: {
        label: 'First obs.',
        width: '15%',
        isSortable: true,
      },
      last_seen: {
        label: 'Last obs.',
        width: '15%',
        isSortable: true,
      },
      weight: {
        label: 'Confidence level',
        isSortable: true,
      },
    };
    return (
      <ListLines
        sortBy={sortBy}
        orderAsc={orderAsc}
        dataColumns={dataColumns}
        handleSort={this.handleSort.bind(this)}
        displayImport={false}
        secondaryAction={true}
      >
        <QueryRenderer
          query={entityStixObservablesLinesQuery}
          variables={{ count: 25, ...paginationOptions }}
          render={({ props }) => (
            <EntityStixObservablesLines
              data={props}
              paginationOptions={paginationOptions}
              entityLink={entityLink}
              dataColumns={dataColumns}
              initialLoading={props === null}
            />
          )}
        />
      </ListLines>
    );
  }

  render() {
    const { entityId, relationType } = this.props;
    const {
      view, targetEntityTypes, sortBy, orderAsc,
    } = this.state;
    const paginationOptions = {
      inferred: false,
      toTypes: targetEntityTypes,
      fromId: entityId,
      relationType,
      orderBy: sortBy,
      orderMode: orderAsc ? 'asc' : 'desc',
    };
    return (
      <div>
        {view === 'lines' ? this.renderLines(paginationOptions) : ''}
        <StixRelationCreationFromEntity
          entityId={entityId}
          targetEntityTypes={['Stix-Observable']}
          allowedRelationshipTypes={[relationType]}
          onlyObservables={true}
          isFrom={false}
          paddingRight={true}
          paginationOptions={paginationOptions}
        />
        <StixObservablesRightBar
          types={targetEntityTypes}
          handleToggle={this.handleToggle.bind(this)}
        />
      </div>
    );
  }
}

EntityStixObservables.propTypes = {
  entityId: PropTypes.string,
  relationType: PropTypes.string,
  entityLink: PropTypes.string,
  classes: PropTypes.object,
  t: PropTypes.func,
  history: PropTypes.object,
};

export default compose(inject18n)(EntityStixObservables);
