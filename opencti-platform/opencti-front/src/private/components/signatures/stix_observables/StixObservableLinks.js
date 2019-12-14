import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import Paper from '@material-ui/core/Paper';
import { createRefetchContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { QueryRenderer } from '../../../../relay/environment';
import inject18n from '../../../../components/i18n';
import ListLines from '../../../../components/list_lines/ListLines';
import StixObservableObservablesLines, {
  stixObservableObservablesLinesQuery,
} from './StixObservableObservablesLines';
import StixObservableRelationCreationFromEntity from '../../common/stix_observable_relations/StixObservableRelationCreationFromEntity';
import StixObservableHeader from './StixObservableHeader';

const styles = () => ({
  paper: {
    minHeight: '100%',
    margin: '5px 0 0 0',
    padding: '25px 15px 15px 15px',
    borderRadius: 6,
  },
});

const StixObservableLinksQuery = graphql`
  query StixObservableLinksQuery($id: String!) {
    stixObservable(id: $id) {
      ...StixObservableLinks_stixObservable
    }
  }
`;

class StixObservableLinks extends Component {
  constructor(props) {
    super(props);
    this.state = {
      sortBy: 'first_seen',
      orderAsc: true,
      searchTerm: '',
      view: 'lines',
    };
  }

  handleSort(field, orderAsc) {
    this.setState({ sortBy: field, orderAsc });
  }

  handleSearch(value) {
    this.setState({ searchTerm: value });
  }

  renderLines(paginationOptions) {
    const { sortBy, orderAsc } = this.state;
    const dataColumns = {
      relationship_type: {
        label: 'Relation',
        width: '15%',
        isSortable: true,
      },
      entity_type: {
        label: 'Entity type',
        width: '15%',
        isSortable: false,
      },
      observable_value: {
        label: 'Observable value',
        width: '25%',
        isSortable: false,
      },
      role_played: {
        label: 'Played role',
        width: '15%',
        isSortable: false,
      },
      first_seen: {
        label: 'First obs.',
        width: '15%',
        isSortable: false,
      },
      last_seen: {
        label: 'Last obs.',
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
        displayImport={true}
        secondaryAction={true}
      >
        <QueryRenderer
          query={stixObservableObservablesLinesQuery}
          variables={{ count: 25, ...paginationOptions }}
          render={({ props }) => (
            <StixObservableObservablesLines
              data={props}
              paginationOptions={paginationOptions}
              dataColumns={dataColumns}
              initialLoading={props === null}
              displayRelation={true}
            />
          )}
        />
      </ListLines>
    );
  }

  render() {
    const {
      view, sortBy, orderAsc, searchTerm,
    } = this.state;
    const { classes, stixObservable } = this.props;
    const paginationOptions = {
      fromId: stixObservable.id,
      search: searchTerm,
      orderBy: sortBy,
      orderMode: orderAsc ? 'asc' : 'desc',
    };
    return (
      <div className={classes.container}>
        <StixObservableHeader stixObservable={stixObservable} />
        <StixObservableRelationCreationFromEntity
          paginationOptions={paginationOptions}
          entityId={stixObservable.id}
          isFrom={true}
        />
        <div className="clearfix" />
        <Paper classes={{ root: classes.paper }} elevation={2}>
          {view === 'lines' ? this.renderLines(paginationOptions) : ''}
        </Paper>
      </div>
    );
  }
}

StixObservableLinks.propTypes = {
  stixObservable: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  history: PropTypes.object,
};

const StixObservableLinksFragment = createRefetchContainer(
  StixObservableLinks,
  {
    stixObservable: graphql`
      fragment StixObservableLinks_stixObservable on StixObservable {
        id
        ...StixObservableHeader_stixObservable
      }
    `,
  },
  StixObservableLinksQuery,
);

export default compose(
  inject18n,
  withStyles(styles),
)(StixObservableLinksFragment);
