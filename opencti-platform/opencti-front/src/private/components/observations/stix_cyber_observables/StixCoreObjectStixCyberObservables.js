import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose, filter, append } from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import { QueryRenderer } from '../../../../relay/environment';
import inject18n from '../../../../components/i18n';
import ListLines from '../../../../components/list_lines/ListLines';
import { UserContext } from '../../../../utils/Security';
import StixCoreObjectStixCyberObservablesLines, {
  stixCoreObjectStixCyberObservablesLinesQuery,
} from './StixCoreObjectStixCyberObservablesLines';
import StixCyberObservablesRightBar from './StixCyberObservablesRightBar';
import StixCoreRelationshipCreationFromEntity from '../../common/stix_core_relationships/StixCoreRelationshipCreationFromEntity';

const styles = () => ({
  container: {
    marginTop: 15,
    paddingBottom: 70,
  },
});

class StixCoreObjectStixCyberObservables extends Component {
  constructor(props) {
    super(props);
    this.state = {
      sortBy: null,
      orderAsc: false,
      searchTerm: '',
      openToType: false,
      toType: 'All',
      targetStixCyberObservableTypes: ['Stix-Cyber-Observable'],
      view: 'lines',
      numberOfElements: { number: 0, symbol: '' },
    };
  }

  handleSort(field, orderAsc) {
    this.setState({ sortBy: field, orderAsc });
  }

  handleSearch(value) {
    this.setState({ searchTerm: value });
  }

  setNumberOfElements(numberOfElements) {
    this.setState({ numberOfElements });
  }

  handleToggle(type) {
    if (this.state.targetStixCyberObservableTypes.includes(type)) {
      this.setState({
        targetStixCyberObservableTypes:
          filter((t) => t !== type, this.state.targetStixCyberObservableTypes)
            .length === 0
            ? ['Stix-Cyber-Observable']
            : filter(
              (t) => t !== type,
              this.state.targetStixCyberObservableTypes,
            ),
      });
    } else {
      this.setState({
        targetStixCyberObservableTypes: append(
          type,
          filter(
            (t) => t !== 'Stix-Cyber-Observable',
            this.state.targetStixCyberObservableTypes,
          ),
        ),
      });
    }
  }

  handleClear() {
    this.setState({ targetStixCyberObservableTypes: [] }, () => this.saveView());
  }

  // eslint-disable-next-line class-methods-use-this
  buildColumns(helper) {
    const isRuntimeSort = helper.isRuntimeFieldEnable();
    return {
      entity_type: {
        label: 'Type',
        width: '15%',
        isSortable: false,
      },
      observable_value: {
        label: 'Value',
        width: '35%',
        isSortable: isRuntimeSort,
      },
      start_time: {
        label: 'First obs.',
        width: '15%',
        isSortable: true,
      },
      stop_time: {
        label: 'Last obs.',
        width: '15%',
        isSortable: true,
      },
      confidence: {
        label: 'Confidence level',
        isSortable: true,
      },
    };
  }

  renderLines(paginationOptions) {
    const { sortBy, orderAsc, numberOfElements } = this.state;
    const { stixCoreObjectLink, isRelationReversed } = this.props;
    return (
        <UserContext.Consumer>
          {({ helper }) => <ListLines
            sortBy={sortBy}
            orderAsc={orderAsc}
            dataColumns={this.buildColumns(helper)}
            handleSort={this.handleSort.bind(this)}
            handleSearch={this.handleSearch.bind(this)}
            displayImport={true}
            secondaryAction={true}
            numberOfElements={numberOfElements}>
            <QueryRenderer
              query={stixCoreObjectStixCyberObservablesLinesQuery}
              variables={{ count: 25, ...paginationOptions }}
              render={({ props }) => (
                <StixCoreObjectStixCyberObservablesLines
                  data={props}
                  paginationOptions={paginationOptions}
                  stixCoreObjectLink={stixCoreObjectLink}
                  dataColumns={this.buildColumns(helper)}
                  initialLoading={props === null}
                  setNumberOfElements={this.setNumberOfElements.bind(this)}
                  isRelationReversed={isRelationReversed}
                />
              )}
            />
          </ListLines>}
       </UserContext.Consumer>
    );
  }

  render() {
    const {
      classes,
      stixCoreObjectId,
      relationshipType,
      noRightBar,
      isRelationReversed,
    } = this.props;
    const {
      view, targetStixCyberObservableTypes, sortBy, orderAsc,
    } = this.state;
    let paginationOptions = {
      fromTypes: targetStixCyberObservableTypes,
      toId: stixCoreObjectId,
      relationship_type: relationshipType || 'stix-core-relationship',
      orderBy: sortBy,
      orderMode: orderAsc ? 'asc' : 'desc',
    };
    if (isRelationReversed) {
      paginationOptions = {
        toTypes: targetStixCyberObservableTypes,
        fromId: stixCoreObjectId,
        relationship_type: relationshipType || 'stix-core-relationship',
        orderBy: sortBy,
        orderMode: orderAsc ? 'asc' : 'desc',
      };
    }
    return (
      <div className={classes.container}>
        {view === 'lines' ? this.renderLines(paginationOptions) : ''}
        <StixCoreRelationshipCreationFromEntity
          entityId={stixCoreObjectId}
          targetStixCyberObservableTypes={['Stix-Cyber-Observable']}
          isRelationReversed={!isRelationReversed}
          allowedRelationshipTypes={
            relationshipType ? [relationshipType] : null
          }
          paddingRight={220}
          paginationOptions={paginationOptions}
        />
        {!noRightBar && (
          <StixCyberObservablesRightBar
            types={targetStixCyberObservableTypes}
            handleToggle={this.handleToggle.bind(this)}
            handleClear={this.handleClear.bind(this)}
          />
        )}
      </div>
    );
  }
}

StixCoreObjectStixCyberObservables.propTypes = {
  stixCoreObjectId: PropTypes.string,
  noRightBar: PropTypes.bool,
  relationshipType: PropTypes.string,
  stixCoreObjectLink: PropTypes.string,
  classes: PropTypes.object,
  t: PropTypes.func,
  history: PropTypes.object,
  isRelationReversed: PropTypes.bool,
};

export default compose(
  inject18n,
  withStyles(styles),
)(StixCoreObjectStixCyberObservables);
