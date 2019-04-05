/* eslint-disable no-nested-ternary */
// TODO Remove no-nested-ternary
import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { CSVLink } from 'react-csv';
import {
  assoc, compose, defaultTo, lensProp, map, over, pipe,
} from 'ramda';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import List from '@material-ui/core/List';
import ListItem from '@material-ui/core/ListItem';
import ListItemIcon from '@material-ui/core/ListItemIcon';
import ListItemText from '@material-ui/core/ListItemText';
import IconButton from '@material-ui/core/IconButton';
import Button from '@material-ui/core/Button';
import Dialog from '@material-ui/core/Dialog';
import DialogContent from '@material-ui/core/DialogContent';
import DialogContentText from '@material-ui/core/DialogContentText';
import DialogTitle from '@material-ui/core/DialogTitle';
import DialogActions from '@material-ui/core/DialogActions';
import CircularProgress from '@material-ui/core/CircularProgress';
import Menu from '@material-ui/core/Menu';
import MenuItem from '@material-ui/core/MenuItem';
import {
  ArrowDropDown,
  ArrowDropUp,
  TableChart,
  SaveAlt,
} from '@material-ui/icons';
import { fetchQuery, QueryRenderer } from '../../relay/environment';
import CitiesLines, { citiesLinesQuery } from './city/CitiesLines';
import inject18n from '../../components/i18n';
import SearchInput from '../../components/SearchInput';
import CityCreation from './city/CityCreation';
import { dateFormat } from '../../utils/Time';

const styles = theme => ({
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
  name: {
    float: 'left',
    width: '60%',
    fontSize: 12,
    fontWeight: '700',
  },
  created_at: {
    float: 'left',
    width: '15%',
    fontSize: 12,
    fontWeight: '700',
  },
  updated_at: {
    float: 'left',
    fontSize: 12,
    fontWeight: '700',
  },
};

const exportCitiesQuery = graphql`
  query CitiesExportCitiesQuery(
    $count: Int!
    $cursor: ID
    $orderBy: CitiesOrdering
    $orderMode: OrderingMode
  ) {
    cities(
      first: $count
      after: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
    ) @connection(key: "Pagination_cities") {
      edges {
        node {
          id
          name
          description
        }
      }
    }
  }
`;

class Cities extends Component {
  constructor(props) {
    super(props);
    this.state = {
      sortBy: 'name',
      orderAsc: true,
      searchTerm: '',
      view: 'lines',
      exportCsvOpen: false,
      exportCsvData: null,
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
      orderBy: this.state.sortBy,
      orderMode: this.state.orderAsc ? 'asc' : 'desc',
    };
    fetchQuery(exportCitiesQuery, {
      count: 2147483647,
      ...paginationOptions,
    }).then((data) => {
      const finalData = pipe(
        map(n => n.node),
        map(n => over(lensProp('description'), defaultTo('-'))(n)),
        map(n => assoc('created', dateFormat(n.created))(n)),
        map(n => assoc('modified', dateFormat(n.modified))(n)),
      )(data.cities.edges);
      this.setState({ exportCsvData: finalData });
    });
  }

  render() {
    const { classes, t } = this.props;
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
                  {this.SortHeader('name', 'Name')}
                  {this.SortHeader('created_at', 'Creation date')}
                  {this.SortHeader('updated_at', 'Modification date')}
                </div>
              }
            />
          </ListItem>
          <QueryRenderer
            query={citiesLinesQuery}
            variables={{ count: 25, ...paginationOptions }}
            render={({ props }) => {
              if (props) {
                return (
                  <CitiesLines
                    data={props}
                    paginationOptions={paginationOptions}
                    searchTerm={this.state.searchTerm}
                  />
                );
              }
              return (
                <CitiesLines
                  data={null}
                  dummy={true}
                  searchTerm={this.state.searchTerm}
                />
              );
            }}
          />
        </List>
        <CityCreation paginationOptions={paginationOptions} />
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
                filename={`${t('Cities')}.csv`}
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

Cities.propTypes = {
  classes: PropTypes.object,
  t: PropTypes.func,
  history: PropTypes.object,
};

export default compose(
  inject18n,
  withStyles(styles),
)(Cities);
