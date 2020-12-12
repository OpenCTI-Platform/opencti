import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import { QueryRenderer } from '../../../relay/environment';
import ListLines from '../../../components/list_lines/ListLines';
import inject18n from '../../../components/i18n';
import StixSightingRelationshipsLines, {
  stixSightingRelationshipsLinesQuery,
} from './stix_sighting_relationships/StixSightingRelationshipsLines';

const styles = (theme) => ({
  container: {
    marginTop: 15,
    paddingBottom: 70,
  },
  bottomNav: {
    zIndex: 1000,
    padding: '10px 274px 10px 84px',
    backgroundColor: theme.palette.navBottom.background,
    display: 'flex',
  },
  chips: {
    display: 'flex',
    flexWrap: 'wrap',
  },
  chip: {
    margin: theme.spacing(1) / 4,
  },
});

class StixSightingRelationships extends Component {
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
    const { entityLink } = this.props;
    // sort only when inferences are disabled or inferences are resolved
    const dataColumns = {
      x_opencti_negative: {
        label: 'Status',
        width: '10%',
        isSortable: true,
      },
      attribute_count: {
        label: 'Count',
        width: '5%',
        isSortable: true,
      },
      name: {
        label: 'Name',
        width: '20%',
        isSortable: false,
      },
      entity_type: {
        label: 'Entity type',
        width: '15%',
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
      confidence: {
        label: 'Confidence level',
        width: '15%',
        isSortable: true,
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
          query={stixSightingRelationshipsLinesQuery}
          variables={{ count: 25, ...paginationOptions }}
          render={({ props }) => (
            <StixSightingRelationshipsLines
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
    const { classes } = this.props;
    const {
      view, searchTerm, sortBy, orderAsc,
    } = this.state;
    const paginationOptions = {
      fromRole: 'stix-sighting-relationship_from',
      search: searchTerm,
      orderBy: sortBy,
      orderMode: orderAsc ? 'asc' : 'desc',
    };
    return (
      <div className={classes.container}>
        {view === 'lines' ? this.renderLines(paginationOptions) : ''}
      </div>
    );
  }
}

StixSightingRelationships.propTypes = {
  classes: PropTypes.object,
  t: PropTypes.func,
  history: PropTypes.object,
};

export default compose(
  inject18n,
  withStyles(styles),
)(StixSightingRelationships);
