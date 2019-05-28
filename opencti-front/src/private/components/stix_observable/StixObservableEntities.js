/* eslint-disable no-nested-ternary */
// TODO Remove no-nested-ternary
import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import {
  compose,
  head,
  map,
  pipe,
  assoc,
  omit,
  mergeRight,
  filter,
  append,
} from 'ramda';
import graphql from 'babel-plugin-relay/macro';
import { CSVLink } from 'react-csv';
import { withStyles } from '@material-ui/core/styles';
import Typography from '@material-ui/core/Typography';
import Paper from '@material-ui/core/Paper';
import Menu from '@material-ui/core/Menu';
import Dialog from '@material-ui/core/Dialog';
import DialogContent from '@material-ui/core/DialogContent';
import DialogContentText from '@material-ui/core/DialogContentText';
import DialogTitle from '@material-ui/core/DialogTitle';
import DialogActions from '@material-ui/core/DialogActions';
import IconButton from '@material-ui/core/IconButton';
import Button from '@material-ui/core/Button';
import MenuItem from '@material-ui/core/MenuItem';
import List from '@material-ui/core/List';
import ListItem from '@material-ui/core/ListItem';
import ListItemIcon from '@material-ui/core/ListItemIcon';
import ListItemText from '@material-ui/core/ListItemText';
import ListItemSecondaryAction from '@material-ui/core/ListItemSecondaryAction';
import CircularProgress from '@material-ui/core/CircularProgress';
import {
  ArrowDropDown,
  ArrowDropUp,
  TableChart,
  SaveAlt,
} from '@material-ui/icons';
import { QueryRenderer, fetchQuery } from '../../../relay/environment';
import {
  currentYear,
  parse,
  yearFormat,
  dateFormat,
} from '../../../utils/Time';
import SearchInput from '../../../components/SearchInput';
import inject18n from '../../../components/i18n';
import StixObservableEntitiesLines, {
  stixObservableEntitiesLinesQuery,
} from './StixObservableEntitiesLines';

const styles = theme => ({
  paper: {
    minHeight: '100%',
    margin: '10px 0 0 0',
    padding: '15px',
    borderRadius: 6,
  },
  container: {
    position: 'relative',
  },
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
  chips: {
    display: 'flex',
    flexWrap: 'wrap',
  },
  chip: {
    margin: theme.spacing(1) / 4,
  },
  views: {
    position: 'absolute',
    top: -65,
    right: 0,
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
    marginLeft: theme.spacing(1),
  },
  icon: {
    marginRight: theme.spacing(1),
    fontSize: 20,
  },
});

const inlineStyles = {
  iconSort: {
    position: 'absolute',
    margin: '0 0 0 5px',
    padding: 0,
    top: '0px',
  },
  entity_type: {
    float: 'left',
    width: '15%',
    fontSize: 12,
    fontWeight: '700',
  },
  name: {
    float: 'left',
    width: '22%',
    fontSize: 12,
    fontWeight: '700',
  },
  role_played: {
    float: 'left',
    width: '15%',
    fontSize: 12,
    fontWeight: '700',
  },
  first_seen: {
    float: 'left',
    width: '15%',
    fontSize: 12,
    fontWeight: '700',
  },
  last_seen: {
    float: 'left',
    width: '15%',
    fontSize: 12,
    fontWeight: '700',
  },
  weight: {
    float: 'left',
    fontSize: 12,
    fontWeight: '700',
  },
};

const firstStixObservableQuery = graphql`
  query StixObservableEntitiesFirstStixObservableQuery(
    $fromId: String
    $relationType: String
    $inferred: Boolean
    $resolveInferences: Boolean
    $resolveRelationType: String
    $resolveRelationRole: String
    $resolveRelationToTypes: [String]
    $resolveViaTypes: [EntityRelation]
    $first: Int
    $orderBy: StixRelationsOrdering
    $orderMode: OrderingMode
  ) {
    stixRelations(
      fromId: $fromId
      relationType: $relationType
      inferred: $inferred
      resolveInferences: $resolveInferences
      resolveRelationType: $resolveRelationType
      resolveRelationRole: $resolveRelationRole
      resolveRelationToTypes: $resolveRelationToTypes
      resolveViaTypes: $resolveViaTypes
      first: $first
      orderBy: $orderBy
      orderMode: $orderMode
    ) {
      edges {
        node {
          id
          first_seen
        }
      }
    }
  }
`;

const exportStixObservablesQuery = graphql`
  query StixObservableEntitiesExportStixRelationsQuery(
    $fromId: String
    $inferred: Boolean
    $relationType: String
    $resolveInferences: Boolean
    $resolveRelationType: String
    $resolveRelationRole: String
    $resolveRelationToTypes: [String]
    $resolveViaTypes: [EntityRelation]
    $firstSeenStart: DateTime
    $firstSeenStop: DateTime
    $lastSeenStart: DateTime
    $lastSeenStop: DateTime
    $weights: [Int]
    $count: Int!
    $cursor: ID
    $orderBy: StixRelationsOrdering
    $orderMode: OrderingMode
  ) {
    stixRelations(
      fromId: $fromId
      inferred: $inferred
      relationType: $relationType
      resolveInferences: $resolveInferences
      resolveRelationType: $resolveRelationType
      resolveRelationRole: $resolveRelationRole
      resolveRelationToTypes: $resolveRelationToTypes
      resolveViaTypes: $resolveViaTypes
      firstSeenStart: $firstSeenStart
      firstSeenStop: $firstSeenStop
      lastSeenStart: $lastSeenStart
      lastSeenStop: $lastSeenStop
      weights: $weights
      first: $count
      after: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
    ) @connection(key: "Pagination_stixRelations") {
      edges {
        node {
          id
          weight
          first_seen
          last_seen
          description
          inferred
          to {
            id
            entity_type
            name
            description
            created_at
            updated_at
          }
        }
      }
    }
  }
`;

class StixObservableEntities extends Component {
  constructor(props) {
    super(props);
    this.state = {
      sortBy: 'first_seen',
      orderAsc: false,
      searchTerm: '',
      firstSeen: 'All years',
      firstSeenFirstYear: currentYear(),
      firstSeenStart: null,
      firstSeenStop: null,
      toType: 'All',
      inferred: true,
      resolveInferences: false,
      view: 'lines',
      anchorExport: null,
      exportCsvOpen: false,
      exportCsvData: null,
    };
  }

  componentDidMount() {
    const {
      entityId,
      relationType,
      resolveRelationType,
      resolveRelationRole,
      resolveRelationToTypes,
      resolveViaTypes,
    } = this.props;
    fetchQuery(firstStixObservableQuery, {
      resolveInferences: true,
      resolveRelationType,
      resolveRelationRole,
      resolveRelationToTypes,
      resolveViaTypes,
      fromId: entityId,
      relationType,
      first: 1,
      orderBy: 'first_seen',
      orderMode: 'asc',
      inferred: true,
    }).then((data) => {
      if (data.stixRelations.edges && data.stixRelations.edges.length > 0) {
        this.setState({
          firstSeenFirstYear: yearFormat(
            head(data.stixRelations.edges).node.first_seen,
          ),
        });
      }
    });
  }

  handleSearch(value) {
    this.setState({ searchTerm: value });
  }

  handleChangeView(mode) {
    this.setState({ view: mode });
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

  handleChangeYear(event) {
    const { value } = event.target;
    if (value !== 'All years') {
      const startDate = `${value}-01-01`;
      const endDate = `${value}-12-31`;
      this.setState({
        firstSeen: value,
        firstSeenStart: parse(startDate).format(),
        firstSeenStop: parse(endDate).format(),
        resolveInferences: true,
        inferred: true,
      });
    } else {
      this.setState({
        firstSeen: value,
        firstSeenStart: null,
        firstSeenStop: null,
      });
    }
  }

  handleChangeInferred() {
    this.setState({
      inferred: !this.state.inferred,
      resolveInferences:
        !this.state.inferred === false ? false : this.state.resolveInferences,
    });
  }

  handleChangeResolveInferences() {
    this.setState({ resolveInferences: !this.state.resolveInferences });
  }

  handleToggle(type) {
    if (this.state.targetEntityTypes.includes(type)) {
      this.setState({
        targetEntityTypes: filter(t => t !== type, this.state.targetEntityTypes),
      });
    } else {
      this.setState({
        targetEntityTypes: append(type, this.state.targetEntityTypes),
      });
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
    const {
      entityId,
      relationType,
      resolveRelationType,
      resolveRelationRole,
      resolveRelationToTypes,
      resolveViaTypes,
    } = this.props;
    const paginationOptions = {
      resolveInferences: this.state.resolveInferences,
      resolveRelationType,
      resolveRelationRole,
      resolveRelationToTypes,
      resolveViaTypes,
      inferred: this.state.inferred,
      fromId: entityId,
      relationType,
      firstSeenStart: this.state.firstSeenStart || null,
      firstSeenStop: this.state.firstSeenStop || null,
      orderBy: this.state.resolveInferences ? this.state.sortBy : null,
      orderMode: this.state.orderAsc ? 'asc' : 'desc',
    };

    fetchQuery(exportStixObservablesQuery, {
      count: 10000,
      ...paginationOptions,
    }).then((data) => {
      const finalData = pipe(
        map(n => n.node),
        map(n => assoc('relationship_description', n.description)(n)),
        map(n => mergeRight(n, n.to)),
        map(n => assoc('first_seen', dateFormat(n.first_seen))(n)),
        map(n => assoc('last_seen', dateFormat(n.last_seen))(n)),
        map(n => omit(
          ['to', 'id', 'inferred', '__typename', 'created_at', 'updated_at'],
          n,
        )),
      )(data.stixRelations.edges);
      this.setState({ exportCsvData: finalData });
    });
  }

  renderLines() {
    const {
      classes,
      entityId,
      relationType,
      resolveRelationType,
      resolveRelationRole,
      resolveRelationToTypes,
      resolveViaTypes,
    } = this.props;
    const paginationOptions = {
      resolveInferences: this.state.resolveInferences,
      resolveRelationType,
      resolveRelationRole,
      resolveRelationToTypes,
      resolveViaTypes,
      inferred: this.state.inferred,
      toTypes: this.state.targetEntityTypes,
      fromId: entityId,
      relationType,
      firstSeenStart: this.state.firstSeenStart || null,
      firstSeenStop: this.state.firstSeenStop || null,
      orderBy: this.state.resolveInferences ? this.state.sortBy : null,
      orderMode: this.state.orderAsc ? 'asc' : 'desc',
    };
    return (
      <List classes={{ root: classes.linesContainer }}>
        <ListItem
          classes={{ root: classes.item }}
          divider={false}
          style={{ paddingTop: 0 }}
        >
          <ListItemIcon>
            <span
              style={{ padding: '0 8px 0 8px', fontWeight: 700, fontSize: 12 }}
            >
              #
            </span>
          </ListItemIcon>
          <ListItemText
            primary={
              <div>
                {this.SortHeader('entity_type', 'Type', true)}
                {this.SortHeader('name', 'Name', true)}
                {this.SortHeader('role_played', 'Role', true)}
                {this.SortHeader('first_seen', 'First seen', true)}
                {this.SortHeader('last_seen', 'Last seen', true)}
                {this.SortHeader('weight', 'Confidence level', true)}
              </div>
            }
          />
          <ListItemSecondaryAction>&nbsp;</ListItemSecondaryAction>
        </ListItem>
        <QueryRenderer
          query={stixObservableEntitiesLinesQuery}
          variables={{ count: 25, ...paginationOptions }}
          render={({ props }) => {
            if (props) {
              return (
                <StixObservableEntitiesLines
                  data={props}
                  paginationOptions={paginationOptions}
                  entityId={entityId}
                />
              );
            }
            return <StixObservableEntitiesLines data={null} dummy={true} />;
          }}
        />
      </List>
    );
  }

  render() {
    const {
      t, classes, entityId, relationType,
    } = this.props;
    const startYear = this.state.firstSeenFirstYear === currentYear()
      ? this.state.firstSeenFirstYear - 1
      : this.state.firstSeenFirstYear;
    const yearsList = [];
    for (let i = startYear; i <= currentYear(); i++) {
      yearsList.push(i);
    }
    return (
      <div style={{ marginTop: 30 }}>
        <Typography variant="h4" gutterBottom={true}>
          {t('Links with threats')}
        </Typography>
        <Paper classes={{ root: classes.paper }} elevation={2}>
          <div className={classes.header}>
            <div style={{ float: 'left' }}>
              <SearchInput
                variant="small"
                onChange={this.handleSearch.bind(this)}
              />
            </div>
            <div style={{ float: 'right', marginTop: -10 }}>
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
          {this.state.view === 'lines' ? this.renderLines() : ''}
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
                  filename={`${entityId}_${relationType}.csv`}
                >
                  {t('Download')}
                </Button>
              ) : (
                ''
              )}
            </DialogActions>
          </Dialog>
        </Paper>
      </div>
    );
  }
}

StixObservableEntities.propTypes = {
  entityId: PropTypes.string,
  resolveRelationType: PropTypes.string,
  resolveRelationRole: PropTypes.string,
  resolveRelationToTypes: PropTypes.array,
  resolveViaTypes: PropTypes.array,
  relationType: PropTypes.string,
  classes: PropTypes.object,
  reportClass: PropTypes.string,
  t: PropTypes.func,
  history: PropTypes.object,
};

export default compose(
  inject18n,
  withStyles(styles),
)(StixObservableEntities);
