import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import Typography from '@material-ui/core/Typography';
import Paper from '@material-ui/core/Paper';
import { QueryRenderer } from '../../../../relay/environment';
import inject18n from '../../../../components/i18n';
import ListLines from '../../../../components/list_lines/ListLines';
import IndicatorEntitiesLines, {
  indicatorEntitiesLinesQuery,
} from './IndicatorEntitiesLines';
import StixRelationCreationFromEntity from '../../common/stix_relations/StixRelationCreationFromEntity';

const styles = () => ({
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: '0 0 0 0',
    padding: '25px 15px 15px 15px',
    borderRadius: 6,
  },
});

class IndicatorEntities extends Component {
  constructor(props) {
    super(props);
    this.state = {
      sortBy: null,
      orderAsc: false,
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
    const { entityId } = this.props;
    const { sortBy, orderAsc } = this.state;
    const dataColumns = {
      entity_type: {
        label: 'Entity type',
        width: '15%',
        isSortable: false,
      },
      name: {
        label: 'Name',
        width: '22%',
        isSortable: false,
      },
      role_played: {
        label: 'Played role',
        width: '15%',
        isSortable: true,
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
        label: 'Confidence',
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
        handleSearch={this.handleSearch.bind(this)}
        displayImport={true}
        secondaryAction={true}
      >
        <QueryRenderer
          query={indicatorEntitiesLinesQuery}
          variables={{ count: 25, ...paginationOptions }}
          render={({ props }) => (
            <IndicatorEntitiesLines
              data={props}
              paginationOptions={paginationOptions}
              dataColumns={dataColumns}
              initialLoading={props === null}
              entityId={entityId}
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
    const {
      classes, t, entityId, relationType,
    } = this.props;
    const paginationOptions = {
      fromId: entityId,
      relationType,
      search: searchTerm,
      orderBy: sortBy,
      orderMode: orderAsc ? 'asc' : 'desc',
    };
    return (
      <div style={{ marginTop: 40 }}>
        <Typography variant="h4" gutterBottom={true} style={{ float: 'left' }}>
          {t('Relations to threats')}
        </Typography>
        <StixRelationCreationFromEntity
          paginationOptions={paginationOptions}
          entityId={entityId}
          variant="inLine"
          isFrom={true}
          targetEntityTypes={[
            'Threat-Actor',
            'Intrusion-Set',
            'Campaign',
            'Incident',
            'Malware',
            'Tool',
            'Vulnerability',
          ]}
        />
        <div className="clearfix" />
        <Paper classes={{ root: classes.paper }} elevation={2}>
          {view === 'lines' ? this.renderLines(paginationOptions) : ''}
        </Paper>
      </div>
    );
  }
}

IndicatorEntities.propTypes = {
  entityId: PropTypes.string,
  relationType: PropTypes.string,
  classes: PropTypes.object,
  t: PropTypes.func,
  history: PropTypes.object,
};

export default compose(
  inject18n,
  withStyles(styles),
)(IndicatorEntities);
