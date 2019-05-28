/* eslint-disable no-nested-ternary */
// TODO Remove no-nested-ternary
import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Link } from 'react-router-dom';
import {
  compose,
  head,
  map,
  includes,
  pipe,
  assoc,
  omit,
  mergeRight,
} from 'ramda';
import graphql from 'babel-plugin-relay/macro';
import { CSVLink } from 'react-csv';
import { withStyles } from '@material-ui/core/styles';
import Drawer from '@material-ui/core/Drawer';
import Grid from '@material-ui/core/Grid';
import Menu from '@material-ui/core/Menu';
import Select from '@material-ui/core/Select';
import Input from '@material-ui/core/Input';
import Chip from '@material-ui/core/Chip';
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
import FormControlLabel from '@material-ui/core/FormControlLabel';
import Switch from '@material-ui/core/Switch';
import ListItemSecondaryAction from '@material-ui/core/ListItemSecondaryAction';
import CircularProgress from '@material-ui/core/CircularProgress';
import {
  ArrowDropDown,
  ArrowDropUp,
  TableChart,
  SaveAlt,
  Explore,
} from '@material-ui/icons';
import { QueryRenderer, fetchQuery } from '../../../relay/environment';
import {
  currentYear,
  parse,
  yearFormat,
  dateFormat,
} from '../../../utils/Time';
import inject18n from '../../../components/i18n';
import EntityStixRelationsLines, {
  entityStixRelationsLinesQuery,
} from './EntityStixRelationsLines';

const styles = theme => ({
  container: {
    position: 'relative',
  },
  bottomNav: {
    zIndex: 1000,
    padding: '10px 274px 10px 84px',
    backgroundColor: theme.palette.navBottom.background,
    display: 'flex',
  },
  linesContainer: {
    marginTop: 20,
    padding: '0 0 90px 0',
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
  name: {
    float: 'left',
    width: '30%',
    fontSize: 12,
    fontWeight: '700',
  },
  entity_type: {
    float: 'left',
    width: '20%',
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

const firstStixRelationQuery = graphql`
  query EntityStixRelationsFirstStixRelationQuery(
    $toTypes: [String]
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
      toTypes: $toTypes
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

const exportStixRelationQuery = graphql`
  query EntityStixRelationsExportStixRelationsQuery(
    $fromId: String
    $toTypes: [String]
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
      toTypes: $toTypes
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

class EntityStixRelations extends Component {
  constructor(props) {
    super(props);
    this.state = {
      sortBy: 'first_seen',
      orderAsc: false,
      firstSeen: 'All years',
      firstSeenFirstYear: currentYear(),
      firstSeenStart: null,
      firstSeenStop: null,
      openToType: false,
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
      targetEntityTypes,
      resolveRelationType,
      resolveRelationRole,
      resolveRelationToTypes,
      resolveViaTypes,
    } = this.props;
    fetchQuery(firstStixRelationQuery, {
      resolveInferences: true,
      resolveRelationType,
      resolveRelationRole,
      resolveRelationToTypes,
      resolveViaTypes,
      toTypes: targetEntityTypes || null,
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

  handleOpenToType() {
    this.setState({ openToType: true });
  }

  handleCloseToType() {
    this.setState({ openToType: false });
  }

  handleChangeEntities(event) {
    const { value } = event.target;
    if (value === 'All' && this.props.targetEntityTypes.length > 1) {
      return this.setState({
        resolveInferences: false,
        openToType: false,
        toType: 'All',
      });
    }
    return this.setState({ openToType: false, toType: value });
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
      targetEntityTypes,
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
      toTypes:
        this.state.toType === 'All' ? targetEntityTypes : [this.state.toType],
      fromId: entityId,
      relationType,
      firstSeenStart: this.state.firstSeenStart || null,
      firstSeenStop: this.state.firstSeenStop || null,
      orderBy: this.state.resolveInferences ? this.state.sortBy : null,
      orderMode: this.state.orderAsc ? 'asc' : 'desc',
    };

    fetchQuery(exportStixRelationQuery, {
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
      entityLink,
      targetEntityTypes,
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
      toTypes:
        this.state.toType === 'All' ? targetEntityTypes : [this.state.toType],
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
                {this.SortHeader('name', 'Name', false)}
                {this.SortHeader('entity_type', 'Entity type', false)}
                {this.SortHeader(
                  'first_seen',
                  'First obs.',
                  this.state.resolveInferences,
                )}
                {this.SortHeader(
                  'last_seen',
                  'Last obs.',
                  this.state.resolveInferences,
                )}
                {this.SortHeader(
                  'weight',
                  'Confidence level',
                  this.state.resolveInferences,
                )}
              </div>
            }
          />
          <ListItemSecondaryAction>&nbsp;</ListItemSecondaryAction>
        </ListItem>
        <QueryRenderer
          query={entityStixRelationsLinesQuery}
          variables={{ count: 25, ...paginationOptions }}
          render={({ props }) => {
            if (props) {
              return (
                <EntityStixRelationsLines
                  data={props}
                  paginationOptions={paginationOptions}
                  entityLink={entityLink}
                  entityId={entityId}
                />
              );
            }
            return <EntityStixRelationsLines data={null} dummy={true} />;
          }}
        />
      </List>
    );
  }

  render() {
    const {
      t,
      classes,
      targetEntityTypes,
      entityId,
      relationType,
      resolveRelationType,
      exploreLink,
    } = this.props;
    const startYear = this.state.firstSeenFirstYear === currentYear()
      ? this.state.firstSeenFirstYear - 1
      : this.state.firstSeenFirstYear;
    const yearsList = [];
    for (let i = startYear; i <= currentYear(); i++) {
      yearsList.push(i);
    }

    return (
      <div className={classes.container}>
        <Drawer
          anchor="bottom"
          variant="permanent"
          classes={{ paper: classes.bottomNav }}
        >
          <Grid container={true} spacing={1}>
            {targetEntityTypes.length > 1 ? (
              <Grid item={true} xs="auto">
                <Select
                  style={{ height: 50, marginRight: 15 }}
                  value={this.state.toType}
                  open={this.state.openToType}
                  onClose={this.handleCloseToType.bind(this)}
                  onOpen={this.handleOpenToType.bind(this)}
                  onChange={this.handleChangeEntities.bind(this)}
                  input={<Input id="entities" />}
                  renderValue={selected => (
                    <div className={classes.chips}>
                      <Chip
                        key={selected}
                        label={t(`entity_${selected.toLowerCase()}`)}
                        className={classes.chip}
                      />
                    </div>
                  )}
                >
                  <MenuItem value="All">{t('All entities')}</MenuItem>
                  {includes('Region', targetEntityTypes)
                  || includes('Identity', targetEntityTypes) ? (
                    <MenuItem value="Region">{t('Region')}</MenuItem>
                    ) : (
                      ''
                    )}
                  {includes('Country', targetEntityTypes)
                  || includes('Identity', targetEntityTypes) ? (
                    <MenuItem value="Country">{t('Country')}</MenuItem>
                    ) : (
                      ''
                    )}
                  {includes('City', targetEntityTypes)
                  || includes('Identity', targetEntityTypes) ? (
                    <MenuItem value="City">{t('City')}</MenuItem>
                    ) : (
                      ''
                    )}
                  {includes('Sector', targetEntityTypes)
                  || includes('Identity', targetEntityTypes) ? (
                    <MenuItem value="Sector">{t('Sector')}</MenuItem>
                    ) : (
                      ''
                    )}
                  {includes('Organization', targetEntityTypes)
                  || includes('Identity', targetEntityTypes) ? (
                    <MenuItem value="Organization">
                      {t('Organization')}
                    </MenuItem>
                    ) : (
                      ''
                    )}
                  {includes('User', targetEntityTypes)
                  || includes('Identity', targetEntityTypes) ? (
                    <MenuItem value="User">{t('Person')}</MenuItem>
                    ) : (
                      ''
                    )}
                  {includes('Threat-Actor', targetEntityTypes)
                  || includes('Identity', targetEntityTypes) ? (
                    <MenuItem value="Threat-Actor">
                      {t('Threat actor')}
                    </MenuItem>
                    ) : (
                      ''
                    )}
                  {includes('Intrusion-Set', targetEntityTypes) ? (
                    <MenuItem value="Intrusion-Set">
                      {t('Intrusion set')}
                    </MenuItem>
                  ) : (
                    ''
                  )}
                  {includes('Campaign', targetEntityTypes) ? (
                    <MenuItem value="Campaign">{t('Campaign')}</MenuItem>
                  ) : (
                    ''
                  )}
                  {includes('Incident', targetEntityTypes) ? (
                    <MenuItem value="Incident">{t('Incident')}</MenuItem>
                  ) : (
                    ''
                  )}
                  {includes('Malware', targetEntityTypes) ? (
                    <MenuItem value="Malware">{t('Malware')}</MenuItem>
                  ) : (
                    ''
                  )}
                  {includes('Tool', targetEntityTypes) ? (
                    <MenuItem value="Tool">{t('Tool')}</MenuItem>
                  ) : (
                    ''
                  )}
                  {includes('Vulnerability', targetEntityTypes) ? (
                    <MenuItem value="Vulnerability">
                      {t('Vulnerability')}
                    </MenuItem>
                  ) : (
                    ''
                  )}
                  {includes('Attack-Pattern', targetEntityTypes) ? (
                    <MenuItem value="Attack-Pattern">
                      {t('Attack pattern')}
                    </MenuItem>
                  ) : (
                    ''
                  )}
                </Select>
              </Grid>
            ) : (
              ''
            )}
            {this.state.toType !== 'All' || targetEntityTypes.length === 1 ? (
              <Grid item={true} xs="auto">
                <Select
                  style={{ width: 170, height: 50, marginRight: 15 }}
                  value={this.state.firstSeen}
                  onChange={this.handleChangeYear.bind(this)}
                  renderValue={selected => (
                    <div className={classes.chips}>
                      <Chip
                        key={selected}
                        label={t(selected)}
                        className={classes.chip}
                      />
                    </div>
                  )}
                >
                  <MenuItem value="All years">{t('All years')}</MenuItem>
                  {map(
                    year => (
                      <MenuItem key={year} value={year}>
                        {year}
                      </MenuItem>
                    ),
                    yearsList,
                  )}
                </Select>
              </Grid>
            ) : (
              ''
            )}
            {resolveRelationType ? (
              <Grid item={true} xs="auto">
                <FormControlLabel
                  style={{ paddingTop: 5, marginRight: 15 }}
                  control={
                    <Switch
                      checked={this.state.inferred}
                      onChange={this.handleChangeInferred.bind(this)}
                      color="primary"
                    />
                  }
                  label={t('Inferences')}
                />
              </Grid>
            ) : (
              ''
            )}
            {this.state.inferred
            && resolveRelationType
            && (this.state.toType !== 'All' || targetEntityTypes.length === 1) ? (
              <Grid item={true} xs="auto">
                <FormControlLabel
                  style={{ paddingTop: 5, marginRight: 15 }}
                  control={
                    <Switch
                      checked={this.state.resolveInferences}
                      onChange={this.handleChangeResolveInferences.bind(this)}
                      color="primary"
                    />
                  }
                  label={t('Details')}
                />
              </Grid>
              ) : (
                ''
              )}
          </Grid>
          {exploreLink ? (
            <div
              style={{
                position: 'absolute',
                top: 22,
                right: 285,
                color: '#ffffff',
              }}
            >
              <Button
                variant="contained"
                size="small"
                color="primary"
                component={Link}
                to={exploreLink}
                className={classes.button}
                disabled={!entityId}
              >
                <Explore className={classes.icon} />
                {t('Explore')}
              </Button>
            </div>
          ) : (
            ''
          )}
        </Drawer>
        <div className={classes.views}>
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
      </div>
    );
  }
}

EntityStixRelations.propTypes = {
  entityId: PropTypes.string,
  resolveRelationType: PropTypes.string,
  resolveRelationRole: PropTypes.string,
  resolveRelationToTypes: PropTypes.array,
  resolveViaTypes: PropTypes.array,
  targetEntityTypes: PropTypes.array,
  entityLink: PropTypes.string,
  relationType: PropTypes.string,
  classes: PropTypes.object,
  reportClass: PropTypes.string,
  t: PropTypes.func,
  history: PropTypes.object,
  exploreLink: PropTypes.string,
};

export default compose(
  inject18n,
  withStyles(styles),
)(EntityStixRelations);
