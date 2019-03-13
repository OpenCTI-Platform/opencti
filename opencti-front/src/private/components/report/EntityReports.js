/* eslint-disable no-nested-ternary */
// TODO Remove no-nested-ternary
import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { CSVLink } from 'react-csv';
import {
  assoc, compose, defaultTo, join,
  lensProp, map, over, pathOr, pipe,
} from 'ramda';
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
import CircularProgress from '@material-ui/core/CircularProgress';
import Button from '@material-ui/core/Button';
import {
  ArrowDropDown, ArrowDropUp, TableChart, SaveAlt,
} from '@material-ui/icons';
import { fetchQuery, QueryRenderer } from '../../../relay/environment';
import inject18n from '../../../components/i18n';
import SearchInput from '../../../components/SearchInput';
import { dateFormat } from '../../../utils/Time';
import { exportReportsQuery } from '../Reports';
import ReportsLines, { reportsLinesQuery } from './ReportsLines';

const styles = theme => ({
  header: {
    margin: '0 0 10px 0',
  },
  linesContainer: {
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
    width: '40%',
    fontSize: 12,
    fontWeight: '700',
  },
  createdByRef: {
    float: 'left',
    width: '20%',
    fontSize: 12,
    fontWeight: '700',
  },
  published: {
    float: 'left',
    width: '15%',
    fontSize: 12,
    fontWeight: '700',
  },
  object_status: {
    float: 'left',
    width: '10%',
    fontSize: 12,
    fontWeight: '700',
    cursor: 'default',
  },
  marking: {
    float: 'left',
    fontSize: 12,
    fontWeight: '700',
    cursor: 'default',
  },
};

class EntityReports extends Component {
  constructor(props) {
    super(props);
    this.state = {
      sortBy: 'published',
      orderAsc: false,
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

  SortHeader(field, label, isSortable) {
    const { t } = this.props;
    if (isSortable) {
      return (
        <div style={inlineStyles[field]} onClick={this.reverseBy.bind(this, field)}>
          <span>{t(label)}</span>
          {this.state.sortBy === field ? this.state.orderAsc ? <ArrowDropDown style={inlineStyles.iconSort}/> : <ArrowDropUp style={inlineStyles.iconSort}/> : ''}
        </div>
      );
    }
    return (
      <div style={inlineStyles[field]}>
        <span>{t(label)}</span>
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
      objectId: this.props.entityId,
      reportClass: this.props.reportClass || '',
      orderBy: this.state.sortBy,
      orderMode: this.state.orderAsc ? 'asc' : 'desc',
    };
    fetchQuery(exportReportsQuery, { count: 10000, ...paginationOptions }).then((data) => {
      const finalData = pipe(
        map(n => n.node),
        map(n => over(lensProp('description'), defaultTo('-'))(n)),
        map(n => assoc('published', dateFormat(n.published))(n)),
        map(n => assoc('created', dateFormat(n.created))(n)),
        map(n => assoc('modified', dateFormat(n.modified))(n)),
        map(n => assoc('createdByRef', pathOr('-', ['createdByRef', 'node', 'name'], n))(n)),
        map(n => assoc('markingDefinitions', pipe(
          pathOr([], ['markingDefinitions', 'edges']),
          map(o => o.node.definition_name),
          join(', '),
        )(n))(n)),
      )(data.reports.edges);
      this.setState({ exportCsvData: finalData });
    });
  }

  render() {
    const {
      classes, t, entityId, reportClass,
    } = this.props;
    const paginationOptions = {
      objectId: entityId,
      reportClass: reportClass || null,
      orderBy: this.state.sortBy,
      orderMode: this.state.orderAsc ? 'asc' : 'desc',
    };
    return (
      <div>
        <div className={classes.header}>
          <div style={{ float: 'left' }}>
            <SearchInput variant='small' onChange={this.handleSearch.bind(this)}/>
          </div>
          <div style={{ float: 'right', marginTop: -10 }}>
            <IconButton color={this.state.view === 'lines' ? 'secondary' : 'primary'}
                        classes={{ root: classes.button }}
                        onClick={this.handleChangeView.bind(this, 'lines')}>
              <TableChart/>
            </IconButton>
            <IconButton onClick={this.handleOpenExport.bind(this)} aria-haspopup='true' color='primary'>
              <SaveAlt/>
            </IconButton>
            <Menu
              anchorEl={this.state.anchorExport}
              open={Boolean(this.state.anchorExport)}
              onClose={this.handleCloseExport.bind(this)}
              style={{ marginTop: 50 }}
            >
              <MenuItem onClick={this.handleDownloadCSV.bind(this)}>{t('CSV file')}</MenuItem>
            </Menu>
          </div>
          <div className='clearfix'/>
        </div>
        <List classes={{ root: classes.linesContainer }}>
          <ListItem classes={{ default: classes.item }} divider={false} style={{ paddingTop: 0 }}>
            <ListItemIcon>
              <span style={{ padding: '0 8px 0 8px', fontWeight: 700, fontSize: 12 }}>#</span>
            </ListItemIcon>
            <ListItemText primary={
              <div>
                {this.SortHeader('name', 'Name', true)}
                {this.SortHeader('createdByRef', 'Author', true)}
                {this.SortHeader('published', 'Publication', true)}
                {this.SortHeader('object_status', 'Status', true)}
                {this.SortHeader('marking', 'Marking', false)}
              </div>
            }/>
          </ListItem>
          <QueryRenderer
            query={reportsLinesQuery}
            variables={{ count: 25, ...paginationOptions }}
            render={({ props }) => {
              if (props) {
                return <ReportsLines data={props} paginationOptions={paginationOptions} searchTerm={this.state.searchTerm}/>;
              }
              return <ReportsLines data={null} dummy={true} searchTerm={this.state.searchTerm}/>;
            }}
          />
        </List>
        <Dialog
          open={this.state.exportCsvOpen}
          onClose={this.handleCloseExportCsv.bind(this)}
          fullWidth={true}
        >
          <DialogTitle>
            {t('Export data in CSV')}
          </DialogTitle>
          <DialogContent>
            {this.state.exportCsvData === null
              ? <div className={this.props.classes.export}><CircularProgress size={40} thickness={2} className={this.props.classes.loaderCircle}/></div>
              : <DialogContentText>{t('The CSV file has been generated with the parameters of the view and is ready for download.')}</DialogContentText>
            }
          </DialogContent>
          <DialogActions>
            <Button onClick={this.handleCloseExportCsv.bind(this)} color='primary'>
              {t('Cancel')}
            </Button>
            {this.state.exportCsvData !== null
              ? <Button component={CSVLink} data={this.state.exportCsvData} separator={';'} enclosingCharacter={'"'} color='primary' filename={`${t('Reports')}.csv`}>
                {t('Download')}
              </Button>
              : ''}
          </DialogActions>
        </Dialog>
      </div>
    );
  }
}

EntityReports.propTypes = {
  entityId: PropTypes.string,
  classes: PropTypes.object,
  reportClass: PropTypes.string,
  t: PropTypes.func,
  history: PropTypes.object,
};

export default compose(
  inject18n,
  withStyles(styles),
)(EntityReports);
