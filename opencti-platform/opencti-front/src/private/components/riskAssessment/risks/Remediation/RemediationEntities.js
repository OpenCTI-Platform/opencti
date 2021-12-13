import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import Typography from '@material-ui/core/Typography';
import Paper from '@material-ui/core/Paper';
import graphql from 'babel-plugin-relay/macro';
import { QueryRenderer as QR } from 'react-relay';
import QueryRendererDarkLight from '../../../../../relay/environmentDarkLight';
import { QueryRenderer } from '../../../../../relay/environment';
import inject18n from '../../../../../components/i18n';
import ListLines from '../../../../../components/list_lines/ListLines';
import RemediationEntitiesLines, {
  remediationEntitiesLinesQuery,
} from './RemediationEntitiesLines';
import StixCoreRelationshipCreationFromEntity from '../../../common/stix_core_relationships/StixCoreRelationshipCreationFromEntity';
import Security, { KNOWLEDGE_KNUPDATE } from '../../../../../utils/Security';
import AddRemediation from './AddRemediation';

const styles = () => ({
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: 0,
    padding: '25px 15px 15px 15px',
    borderRadius: 6,
  },
});

const remediationEntitiesQuery = graphql`
  query RemediationEntitiesQuery($id: ID!) {
    risk(id: $id) {
      id
      name
    }
  }
`;

class RemediationEntities extends Component {
  constructor(props) {
    super(props);
    this.state = {
      sortBy: null,
      orderAsc: false,
      searchTerm: '',
      view: 'lines',
      relationReversed: false,
    };
  }

  handleReverseRelation() {
    this.setState({ relationReversed: !this.state.relationReversed });
  }

  handleSort(field, orderAsc) {
    this.setState({ sortBy: field, orderAsc });
  }

  handleSearch(value) {
    this.setState({ searchTerm: value });
  }

  renderLines(paginationOptions) {
    const { sortBy, orderAsc } = this.state;
    const { entityId } = this.props;
    const dataColumns = {
      relationship_type: {
        label: 'Title',
        width: '15%',
        isSortable: true,
      },
      entity_type: {
        label: 'Response type',
        width: '15%',
        isSortable: false,
      },
      name: {
        label: 'Lifecycle',
        width: '15%',
        isSortable: false,
      },
      start_time: {
        label: 'Decision Maker',
        width: '15%',
        isSortable: true,
      },
      stop_time: {
        label: 'Start Date',
        width: '15%',
        isSortable: true,
      },
      confidence: {
        label: 'End Date',
        width: '12%',
        isSortable: true,
      },
      source: {
        label: 'Source',
        width: '12%',
        isSortable: true,
      },
    };
    return (
      <ListLines
        sortBy={sortBy}
        orderAsc={orderAsc}
        dataColumns={dataColumns}
        handleSort={this.handleSort.bind(this)}
        // handleSearch={this.handleSearch.bind(this)}
        displayImport={true}
        secondaryAction={true}
        searchVariant="inDrawer2"
      >
        {/* <QueryRenderer */}
        <QR
          environment={QueryRendererDarkLight}
          query={remediationEntitiesQuery}
          variables={{ id: 'ac5a1fdb-23fd-4e43-9b8d-7a7897ba91a8' }}
          render={({ props }) => {
            console.log('RemediationEntitiesData', props);
            return (<RemediationEntitiesLines
              data={props}
              paginationOptions={paginationOptions}
              dataColumns={dataColumns}
              initialLoading={props === null}
              displayRelation={true}
              entityId={entityId}
            />
            );
          }}
        />
      </ListLines>
    );
  }

  render() {
    const {
      view,
      sortBy,
      orderAsc,
      searchTerm,
      relationReversed,
    } = this.state;
    const { classes, t, entityId } = this.props;
    const paginationOptions = {
      elementId: entityId,
      search: searchTerm,
      orderBy: sortBy,
      orderMode: orderAsc ? 'asc' : 'desc',
    };
    return (
      <div style={{ height: '100%' }}>
        <div className="clearfix" />
        <Paper classes={{ root: classes.paper }} elevation={2}>
          {view === 'lines' ? this.renderLines(paginationOptions) : ''}
        </Paper>
      </div>
    );
  }
}

RemediationEntities.propTypes = {
  entityId: PropTypes.string,
  relationship_type: PropTypes.string,
  classes: PropTypes.object,
  t: PropTypes.func,
  history: PropTypes.object,
};

export default compose(
  inject18n,
  withStyles(styles),
)(RemediationEntities);
