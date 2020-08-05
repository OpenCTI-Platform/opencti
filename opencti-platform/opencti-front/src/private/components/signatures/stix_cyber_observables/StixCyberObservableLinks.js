import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import Paper from '@material-ui/core/Paper';
import { createRefetchContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import Grid from '@material-ui/core/Grid';
import Typography from '@material-ui/core/Typography';
import StixCyberObservableHeader from './StixCyberObservableHeader';
import StixCyberObservableRelationCreationFromEntity from '../../common/stix_cyber_observable_relationships/StixCyberObservableRelationshipCreationFromEntity';
import StixCyberObservableObservablesLines, {
  stixCyberObservableObservablesLinesQuery,
} from './StixCyberObservableObservablesLines';
import ListLines from '../../../../components/list_lines/ListLines';
import inject18n from '../../../../components/i18n';
import { QueryRenderer } from '../../../../relay/environment';
import StixCyberObservableEnrichment from './StixCyberObservableEnrichment';

const styles = () => ({
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: 0,
    padding: '25px 15px 15px 15px',
    borderRadius: 6,
  },
});

const StixCyberObservableLinksQuery = graphql`
  query StixCyberObservableLinksQuery($id: String!) {
    stixCyberObservable(id: $id) {
      ...StixCyberObservableLinks_stixCyberObservable
    }
  }
`;

class StixCyberObservableLinks extends Component {
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
          query={stixCyberObservableObservablesLinesQuery}
          variables={{ count: 25, ...paginationOptions }}
          render={({ props }) => (
            <StixCyberObservableObservablesLines
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
    const { classes, stixCyberObservable, t } = this.props;
    const paginationOptions = {
      fromId: stixCyberObservable.id,
      search: searchTerm,
      orderBy: sortBy,
      orderMode: orderAsc ? 'asc' : 'desc',
    };
    return (
      <div>
        <StixCyberObservableHeader stixCyberObservable={stixCyberObservable} />
        <Grid
          container={true}
          spacing={3}
          classes={{ container: classes.gridContainer }}
        >
          <Grid item={true} xs={9}>
            <Typography
              variant="h4"
              gutterBottom={true}
              style={{ float: 'left' }}
            >
              {t('Relations')}
            </Typography>
            <StixCyberObservableRelationCreationFromEntity
              paginationOptions={paginationOptions}
              entityId={stixCyberObservable.id}
              isRelationReversed={false}
              variant="inLine"
            />
            <div className="clearfix" />
            <Paper classes={{ root: classes.paper }} elevation={2}>
              {view === 'lines' ? this.renderLines(paginationOptions) : ''}
            </Paper>
          </Grid>
          <Grid item={true} xs={3}>
            <Typography variant="h4" gutterBottom={true}>
              {t('Enrichment connectors')}
            </Typography>
            <StixCyberObservableEnrichment
              stixCyberObservable={stixCyberObservable}
            />
          </Grid>
        </Grid>
      </div>
    );
  }
}

StixCyberObservableLinks.propTypes = {
  stixCyberObservable: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  history: PropTypes.object,
};

const StixCyberObservableLinksFragment = createRefetchContainer(
  StixCyberObservableLinks,
  {
    stixCyberObservable: graphql`
      fragment StixCyberObservableLinks_stixCyberObservable on StixCyberObservable {
        id
        entity_type
        ...StixCyberObservableEnrichment_stixCyberObservable
        ...StixCyberObservableHeader_stixCyberObservable
      }
    `,
  },
  StixCyberObservableLinksQuery,
);

export default compose(
  inject18n,
  withStyles(styles),
)(StixCyberObservableLinksFragment);
