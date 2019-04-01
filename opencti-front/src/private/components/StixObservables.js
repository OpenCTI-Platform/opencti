/* eslint-disable no-nested-ternary */
// TODO Remove no-nested-ternary
import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { CSVLink } from 'react-csv';
import {
  assoc, compose, join, map, pathOr, pipe, append, filter,
} from 'ramda';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Menu from '@material-ui/core/Menu';
import MenuItem from '@material-ui/core/MenuItem';
import List from '@material-ui/core/List';
import ListItem from '@material-ui/core/ListItem';
import ListItemIcon from '@material-ui/core/ListItemIcon';
import ListItemText from '@material-ui/core/ListItemText';
import Dialog from '@material-ui/core/Dialog';
import DialogContent from '@material-ui/core/DialogContent';
import DialogContentText from '@material-ui/core/DialogContentText';
import DialogTitle from '@material-ui/core/DialogTitle';
import DialogActions from '@material-ui/core/DialogActions';
import IconButton from '@material-ui/core/IconButton';
import Button from '@material-ui/core/Button';
import CircularProgress from '@material-ui/core/CircularProgress';
import {
  ArrowDropDown,
  ArrowDropUp,
  TableChart,
  SaveAlt,
} from '@material-ui/icons';
import { fetchQuery, QueryRenderer } from '../../relay/environment';
import StixObservablesLines, {
  stixObservablesLinesQuery,
} from './stix_observable/StixObservablesLines';
import SearchInput from '../../components/SearchInput';
import inject18n from '../../components/i18n';
import { dateFormat } from '../../utils/Time';
import StixObservablesRightBar from './stix_observable/StixObservablesRightBar';

const styles = theme => ({
  container: {
    margin: 0,
    padding: '0 260px 0 0',
  },
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
  export: {
    width: '100%',
    paddingTop: 10,
    textAlign: 'center',
  },
  loaderCircle: {
    display: 'inline-block',
  },
  rightIcon: {
    marginLeft: theme.spacing.unit,
  },
});

const inlineStyles = {
  iconSort: {
    position: 'absolute',
    margin: '-3px 0 0 5px',
    padding: 0,
    top: '0px',
  },
  entity_type: {
    float: 'left',
    width: '20%',
    fontSize: 12,
    fontWeight: '700',
  },
  observable_value: {
    float: 'left',
    width: '40%',
    fontSize: 12,
    fontWeight: '700',
  },
  created_at: {
    float: 'left',
    width: '15%',
    fontSize: 12,
    fontWeight: '700',
  },
  marking: {
    float: 'left',
    fontSize: 12,
    fontWeight: '700',
    cursor: 'default',
  },
};

export const exportStixObservablesQuery = graphql`
  query StixObservablesExportStixObservablesQuery(
    $count: Int!
    $cursor: ID
    $orderBy: StixObservablesOrdering
    $orderMode: OrderingMode
  ) {
    stixObservables(
      first: $count
      after: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
    ) @connection(key: "Pagination_stixObservables") {
      edges {
        node {
          id
          entity_type
          observable_value
          created_at
          markingDefinitions {
            edges {
              node {
                id
                definition
              }
            }
          }
        }
      }
    }
  }
`;

class StixObservables extends Component {
  constructor(props) {
    super(props);
    this.state = {
      sortBy: 'created_at',
      orderAsc: false,
      searchTerm: '',
      view: 'lines',
      exportCsvOpen: false,
      exportCsvData: null,
      types: [],
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

  SortHeader(field, label, isSortable) {
    const { t } = this.props;
    if (isSortable) {
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
    return (
      <div style={inlineStyles[field]}>
        <span>{t(label)}</span>
      </div>
    );
  }

  handleToggle(type) {
    if (this.state.types.includes(type)) {
      this.setState({ types: filter(t => t !== type, this.state.types) });
    } else {
      this.setState({ types: append(type, this.state.types) });
    }
  }

  handleOpenExport(event) {
    this.setState({ anchorExport: event.currentTarget });
  }

  handleCloseExport() {
    this.setState({ anchorExport: null });
  }

  handleCloseExportCsv() {
    this.setState({ exportCsvOpen: false, exportCsvData: null });
  }

  handleDownloadCSV() {
    this.handleCloseExport();
    this.setState({ exportCsvOpen: true });
    const paginationOptions = {
      types: this.state.types.length > 0 ? this.state.types : null,
      orderBy: this.state.sortBy,
      orderMode: this.state.orderAsc ? 'asc' : 'desc',
    };
    fetchQuery(exportStixObservablesQuery, {
      count: 10000,
      ...paginationOptions,
    }).then((data) => {
      const finalData = pipe(
        map(n => n.node),
        map(n => assoc('created_at', dateFormat(n.created_at))(n)),
        map(n => assoc(
          'markingDefinitions',
          pipe(
            pathOr([], ['markingDefinitions', 'edges']),
            map(o => o.node.definition_name),
            join(', '),
          )(n),
        )(n)),
      )(data.stixObservables.edges);
      this.setState({ exportCsvData: finalData });
    });
  }

  render() {
    const { classes, t } = this.props;
    const paginationOptions = {
      types: this.state.types.length > 0 ? this.state.types : null,
      orderBy: this.state.sortBy,
      orderMode: this.state.orderAsc ? 'asc' : 'desc',
    };
    return (
      <div className={classes.container}>
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
            <IconButton
              onClick={this.handleOpenExport.bind(this)}
              aria-haspopup="true"
              color="primary"
            >
              <SaveAlt />
            </IconButton>
            <Menu
              anchorEl={this.state.anchorExport}
              open={Boolean(this.state.anchorExport)}
              onClose={this.handleCloseExport.bind(this)}
              style={{ marginTop: 50 }}
            >
              <MenuItem onClick={this.handleDownloadCSV.bind(this)}>
                {t('CSV file')}
              </MenuItem>
            </Menu>
          </div>
          <div className="clearfix" />
        </div>
        <List classes={{ root: classes.linesContainer }}>
          <ListItem
            classes={{ default: classes.item }}
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
                  {this.SortHeader('entity_type', 'Type', true)}
                  {this.SortHeader('observable_value', 'Value', true)}
                  {this.SortHeader('created_at', 'Creation date', true)}
                  {this.SortHeader('marking', 'Marking', false)}
                </div>
              }
            />
          </ListItem>
          <QueryRenderer
            query={stixObservablesLinesQuery}
            variables={{ count: 25, ...paginationOptions }}
            render={({ props }) => {
              if (props) {
                return (
                  <StixObservablesLines
                    data={props}
                    paginationOptions={paginationOptions}
                    searchTerm={this.state.searchTerm}
                  />
                );
              }
              return (
                <StixObservablesLines
                  data={null}
                  dummy={true}
                  searchTerm={this.state.searchTerm}
                />
              );
            }}
          />
        </List>
        <StixObservablesRightBar
          types={this.state.types}
          handleToggle={this.handleToggle.bind(this)}
        />
        <Dialog
          open={this.state.exportCsvOpen}
          onClose={this.handleCloseExportCsv.bind(this)}
          fullWidth={true}
        >
          <DialogTitle>{t('Export data in CSV')}</DialogTitle>
          <DialogContent>
            {this.state.exportCsvData === null ? (
              <div className={this.props.classes.export}>
                <CircularProgress
                  size={40}
                  thickness={2}
                  className={this.props.classes.loaderCircle}
                />
              </div>
            ) : (
              <DialogContentText>
                {t(
                  'The CSV file has been generated with the parameters of the view and is ready for download.',
                )}
              </DialogContentText>
            )}
          </DialogContent>
          <DialogActions>
            <Button
              onClick={this.handleCloseExportCsv.bind(this)}
              color="primary"
            >
              {t('Cancel')}
            </Button>
            {this.state.exportCsvData !== null ? (
              <Button
                component={CSVLink}
                data={this.state.exportCsvData}
                separator={';'}
                enclosingCharacter={'"'}
                color="primary"
                filename={`${t('Observables')}.csv`}
              >
                {t('Download')}
              </Button>
            ) : (
              ''
            )}
          </DialogActions>
        </Dialog>
      </div>
    );
  }
}

StixObservables.propTypes = {
  classes: PropTypes.object,
  t: PropTypes.func,
  history: PropTypes.object,
};

export default compose(
  inject18n,
  withStyles(styles),
)(StixObservables);
