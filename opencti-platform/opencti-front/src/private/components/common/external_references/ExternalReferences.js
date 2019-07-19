/* eslint-disable no-nested-ternary */
// TODO Remove no-nested-ternary
import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import {
  assoc, compose, defaultTo, lensProp, map, over, pipe,
} from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import List from '@material-ui/core/List';
import ListItem from '@material-ui/core/ListItem';
import ListItemIcon from '@material-ui/core/ListItemIcon';
import ListItemText from '@material-ui/core/ListItemText';
import IconButton from '@material-ui/core/IconButton';
import { ArrowDropDown, ArrowDropUp, TableChart } from '@material-ui/icons';
import graphql from 'babel-plugin-relay/macro';
import { fetchQuery, QueryRenderer } from '../../../../relay/environment';
import ExternalReferencesLines, {
  externalReferencesLinesQuery,
} from './ExternalReferencesLines';
import inject18n from '../../../../components/i18n';
import SearchInput from '../../../../components/SearchInput';
import StixDomainEntitiesImportData from '../stix_domain_entities/StixDomainEntitiesImportData';
import StixDomainEntitiesExportData from '../stix_domain_entities/StixDomainEntitiesExportData';
import ExternalReferenceCreation from './ExternalReferenceCreation';
import { dateFormat } from '../../../../utils/Time';

const styles = () => ({
  header: {
    margin: '0 0 10px 0',
  },
  linesContainer: {
    marginTop: 0,
    paddingTop: 0,
  },
  item: {
    paddingLeft: 10,
    textTransform: 'uppercase',
    cursor: 'pointer',
  },
  inputLabel: {
    float: 'left',
  },
  sortIcon: {
    float: 'left',
    margin: '-5px 0 0 15px',
  },
});

const inlineStyles = {
  iconSort: {
    position: 'absolute',
    margin: '0 0 0 5px',
    padding: 0,
    top: '0px',
  },
  source_name: {
    float: 'left',
    width: '15%',
    fontSize: 12,
    fontWeight: '700',
  },
  external_id: {
    float: 'left',
    width: '10%',
    fontSize: 12,
    fontWeight: '700',
  },
  url: {
    float: 'left',
    width: '50%',
    fontSize: 12,
    fontWeight: '700',
  },
  created: {
    float: 'left',
    fontSize: 12,
    fontWeight: '700',
  },
};

export const exportExternalReferencesQuery = graphql`
  query ExternalReferencesExportExternalReferencesQuery(
    $count: Int!
    $cursor: ID
    $orderBy: ExternalReferencesOrdering
    $orderMode: OrderingMode
  ) {
    externalReferences(
      first: $count
      after: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
    ) @connection(key: "Pagination_externalReferences") {
      edges {
        node {
          id
          source_name
          description
          url
          hash
          external_id
          created
          modified
        }
      }
    }
  }
`;

class ExternalReferences extends Component {
  constructor(props) {
    super(props);
    this.state = {
      sortBy: 'created',
      orderAsc: false,
      searchTerm: '',
      view: 'lines',
      csvData: null,
    };
  }

  handleChangeView(mode) {
    this.setState({ view: mode });
  }

  handleSearch(value) {
    this.setState({ searchTerm: value });
  }

  reverseBy(field) {
    this.setState({ sortBy: field, orderAsc: !this.state.orderAsc });
  }

  SortHeader(field, label) {
    const { t } = this.props;
    return (
      <div
        style={inlineStyles[field]}
        onClick={this.reverseBy.bind(this, field)}
      >
        <span>{t(label)}</span>
        {this.state.sortBy === field ? (
          this.state.orderAsc ? (
            <ArrowDropDown style={inlineStyles.iconSort} />
          ) : (
            <ArrowDropUp style={inlineStyles.iconSort} />
          )
        ) : (
          ''
        )}
      </div>
    );
  }

  handleGenerateCSV() {
    this.setState({ csvData: null });
    const paginationOptions = {
      orderBy: this.state.sortBy,
      orderMode: this.state.orderAsc ? 'asc' : 'desc',
    };
    fetchQuery(exportExternalReferencesQuery, {
      count: 90000,
      ...paginationOptions,
    }).then((data) => {
      const finalData = pipe(
        map(n => n.node),
        map(n => over(lensProp('description'), defaultTo('-'))(n)),
        map(n => assoc('created', dateFormat(n.created))(n)),
        map(n => assoc('modified', dateFormat(n.modified))(n)),
      )(data.externalReferences.edges);
      this.setState({ csvData: finalData });
    });
  }

  render() {
    const { classes } = this.props;
    const paginationOptions = {
      orderBy: this.state.sortBy,
      orderMode: this.state.orderAsc ? 'asc' : 'desc',
    };
    return (
      <div>
        <div className={classes.header}>
          <div style={{ float: 'left', marginTop: -10 }}>
            <SearchInput
              variant="small"
              onChange={this.handleSearch.bind(this)}
            />
          </div>
          <div style={{ float: 'right', marginTop: -20 }}>
            <IconButton
              color={this.state.view === 'lines' ? 'secondary' : 'primary'}
              classes={{ root: classes.button }}
              onClick={this.handleChangeView.bind(this, 'lines')}
            >
              <TableChart />
            </IconButton>
            <StixDomainEntitiesImportData />
            <StixDomainEntitiesExportData
              fileName="External references"
              handleGenerateCSV={this.handleGenerateCSV.bind(this)}
              csvData={this.state.csvData}
            />
          </div>
          <div className="clearfix" />
        </div>
        <List classes={{ root: classes.linesContainer }}>
          <ListItem
            classes={{ root: classes.item }}
            divider={false}
            style={{ paddingTop: 0 }}
          >
            <ListItemIcon>
              <span
                style={{
                  padding: '0 8px 0 8px',
                  fontWeight: 700,
                  fontSize: 12,
                }}
              >
                #
              </span>
            </ListItemIcon>
            <ListItemText
              primary={
                <div>
                  {this.SortHeader('source_name', 'Source name')}
                  {this.SortHeader('external_id', 'External ID')}
                  {this.SortHeader('url', 'URL')}
                  {this.SortHeader('created', 'Creation date')}
                </div>
              }
            />
          </ListItem>
          <QueryRenderer
            query={externalReferencesLinesQuery}
            variables={{
              count: 25,
              orderBy: this.state.sortBy,
              orderMode: this.state.orderAsc ? 'asc' : 'desc',
            }}
            render={({ props }) => {
              if (props) {
                return (
                  <ExternalReferencesLines
                    data={props}
                    paginationOptions={paginationOptions}
                    searchTerm={this.state.searchTerm}
                  />
                );
              }
              return (
                <ExternalReferencesLines
                  data={null}
                  dummy={true}
                  searchTerm={this.state.searchTerm}
                />
              );
            }}
          />
        </List>
        <ExternalReferenceCreation paginationOptions={paginationOptions} />
      </div>
    );
  }
}

ExternalReferences.propTypes = {
  classes: PropTypes.object,
  t: PropTypes.func,
  history: PropTypes.object,
};

export default compose(
  inject18n,
  withStyles(styles),
)(ExternalReferences);
