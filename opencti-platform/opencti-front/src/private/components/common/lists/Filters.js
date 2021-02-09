import React, { Component } from 'react';
import {
  compose,
  pathOr,
  pipe,
  map,
  union,
  filter,
  includes,
  toPairs,
  assoc,
  dissoc,
  last,
  isEmpty,
  uniqBy,
  prop,
} from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import Grid from '@material-ui/core/Grid';
import { KeyboardDatePicker } from '@material-ui/pickers';
import Autocomplete from '@material-ui/lab/Autocomplete';
import TextField from '@material-ui/core/TextField';
import Popover from '@material-ui/core/Popover';
import IconButton from '@material-ui/core/IconButton';
import { FilterListOutlined } from '@material-ui/icons';
import * as PropTypes from 'prop-types';
import Tooltip from '@material-ui/core/Tooltip';
import { ToyBrickSearchOutline } from 'mdi-material-ui';
import DialogTitle from '@material-ui/core/DialogTitle';
import DialogContent from '@material-ui/core/DialogContent';
import Dialog from '@material-ui/core/Dialog';
import Chip from '@material-ui/core/Chip';
import { withRouter } from 'react-router-dom';
import DialogActions from '@material-ui/core/DialogActions';
import Button from '@material-ui/core/Button';
import { fetchQuery } from '../../../../relay/environment';
import inject18n from '../../../../components/i18n';
import { identityCreationIdentitiesSearchQuery } from '../identities/IdentityCreation';
import { labelsSearchQuery } from '../../settings/LabelsQuery';
import { attributesSearchQuery } from '../../settings/AttributesQuery';
import { markingDefinitionsLinesSearchQuery } from '../../settings/marking_definitions/MarkingDefinitionsLines';
import ItemIcon from '../../../../components/ItemIcon';
import { truncate } from '../../../../utils/String';

const styles = (theme) => ({
  filters: {
    float: 'left',
    margin: '-8px 0 0 -5px',
  },
  filtersDialog: {
    margin: '0 0 20px 0',
  },
  container: {
    width: 490,
    padding: 20,
  },
  icon: {
    paddingTop: 4,
    display: 'inline-block',
    color: theme.palette.primary.main,
  },
  text: {
    display: 'inline-block',
    flexGrow: 1,
    marginLeft: 10,
  },
  autocomplete: {
    float: 'left',
    margin: '5px 10px 0 10px',
    width: 200,
  },
  button: {
    marginLeft: theme.spacing(2),
  },
  filter: {
    marginRight: 10,
  },
  operator: {
    fontFamily: 'Consolas, monaco, monospace',
    backgroundColor: 'rgba(64, 193, 255, 0.2)',
    marginRight: 10,
  },
});

const directFilters = ['report_types'];

class Filters extends Component {
  constructor(props) {
    super(props);
    this.anchorEl = React.createRef();
    this.state = {
      open: false,
      anchorEl: null,
      entities: {},
      filters: {},
      keyword: '',
    };
  }

  handleOpenFilters(event) {
    this.setState({ open: true, anchorEl: event.currentTarget });
  }

  handleCloseFilters() {
    this.setState({ open: false, anchorEl: null });
  }

  searchEntities(filterKey, event) {
    const { t } = this.props;
    switch (filterKey) {
      case 'createdBy':
        fetchQuery(identityCreationIdentitiesSearchQuery, {
          types: ['User', 'Organization'],
          search: event && event.target.value !== 0 ? event.target.value : '',
          first: 10,
        }).then((data) => {
          const entities = pipe(
            pathOr([], ['identities', 'edges']),
            map((n) => ({
              label: n.node.name,
              value: n.node.id,
              type: n.node.entity_type,
            })),
          )(data);
          this.setState({
            entities: { createdBy: union(this.state.entities, entities) },
          });
        });
        break;
      case 'markedBy':
        fetchQuery(markingDefinitionsLinesSearchQuery, {
          search: event && event.target.value !== 0 ? event.target.value : '',
          first: 10,
        }).then((data) => {
          const entities = pipe(
            pathOr([], ['markingDefinitions', 'edges']),
            map((n) => ({
              label: n.node.definition,
              value: n.node.id,
              type: 'Marking-Definition',
              color: n.node.x_opencti_color,
            })),
          )(data);
          this.setState({
            entities: {
              markedBy: union(this.state.entities, entities),
            },
          });
        });
        break;
      case 'labelledBy':
        fetchQuery(labelsSearchQuery, {
          search: event && event.target.value !== 0 ? event.target.value : '',
          first: 10,
        }).then((data) => {
          const entities = pipe(
            pathOr([], ['labels', 'edges']),
            map((n) => ({
              label: n.node.value,
              value: n.node.id,
              type: 'Label',
              color: n.node.color,
            })),
          )(data);
          this.setState({
            entities: { labelledBy: union(this.state.entities, entities) },
          });
        });
        break;
      case 'x_opencti_base_score_gt':
        this.setState({
          entities: {
            x_opencti_base_score_gt: union(
              this.state.entities,
              pipe(
                map((n) => ({
                  label: n,
                  value: n,
                  type: 'attribute',
                })),
              )(['2', '4', '6', '8']),
            ),
          },
        });
        break;
      case 'confidence_gt':
        this.setState({
          entities: {
            confidence_gt: union(
              this.state.entities,
              pipe(
                map((n) => ({
                  label: t(`confidence_${n.toString()}`),
                  value: n,
                  type: 'attribute',
                })),
              )(['0', '15', '50', '75', '85']),
            ),
          },
        });
        break;
      case 'x_opencti_base_severity':
        fetchQuery(attributesSearchQuery, {
          fieldKey: 'x_opencti_base_severity',
          search: event && event.target.value !== 0 ? event.target.value : '',
          first: 10,
        }).then((data) => {
          const entities = pipe(
            pathOr([], ['attributes', 'edges']),
            map((n) => ({
              label: n.node.value,
              value: n.node.value,
              type: 'attribute',
            })),
          )(data);
          this.setState({
            entities: {
              x_opencti_base_severity: union(this.state.entities, entities),
            },
          });
        });
        break;
      case 'x_opencti_attack_vector':
        fetchQuery(attributesSearchQuery, {
          fieldKey: 'x_opencti_attack_vector',
          search: event && event.target.value !== 0 ? event.target.value : '',
          first: 10,
        }).then((data) => {
          const entities = pipe(
            pathOr([], ['attributes', 'edges']),
            map((n) => ({
              label: n.node.value,
              value: n.node.value,
              type: 'attribute',
            })),
          )(data);
          this.setState({
            entities: {
              x_opencti_attack_vector: union(this.state.entities, entities),
            },
          });
        });
        break;
      case 'x_opencti_report_status':
        fetchQuery(attributesSearchQuery, {
          fieldKey: 'x_opencti_report_status',
          search: event && event.target.value !== 0 ? event.target.value : '',
          first: 10,
        }).then((data) => {
          const entities = pipe(
            pathOr([], ['attributes', 'edges']),
            map((n) => ({
              label: t(`report_status_${n.node.value}`),
              value: n.node.value,
              type: 'attribute',
            })),
          )(data);
          this.setState({
            entities: {
              x_opencti_report_status: union(this.state.entities, entities),
            },
          });
        });
        break;
      case 'x_opencti_organization_type':
        fetchQuery(attributesSearchQuery, {
          fieldKey: 'x_opencti_organization_type',
          search: event && event.target.value !== 0 ? event.target.value : '',
          first: 10,
        }).then((data) => {
          const entities = pipe(
            pathOr([], ['attributes', 'edges']),
            map((n) => ({
              label: n.node.value,
              value: n.node.value,
              type: 'attribute',
            })),
          )(data);
          this.setState({
            entities: {
              x_opencti_organization_type: union(this.state.entities, entities),
            },
          });
        });
        break;
      case 'report_types':
        fetchQuery(attributesSearchQuery, {
          key: 'report_types',
          search: event && event.target.value !== 0 ? event.target.value : '',
          first: 10,
        }).then((data) => {
          const entities = pipe(
            pathOr([], ['attributes', 'edges']),
            map((n) => ({
              label: t(n.node.value),
              value: n.node.value,
              type: 'attribute',
            })),
          )(data);
          this.setState({
            entities: {
              report_types: union(this.state.entities, entities),
            },
          });
        });
        break;
      default:
        this.setState({ entities: union(this.state.entities, []) });
    }
  }

  handleChange(filterKey, event, value) {
    if (value) {
      if (this.props.variant === 'dialog') {
        this.handleAddFilter(filterKey, value.value, value.label, event);
      } else {
        this.props.handleAddFilter(filterKey, value.value, value.label, event);
      }
    }
  }

  handleChangeDate(filterKey, date, value) {
    if (date && value && date.toISOString()) {
      if (this.props.variant === 'dialog') {
        this.handleAddFilter(filterKey, date.toISOString(), value);
      } else {
        this.props.handleAddFilter(filterKey, date.toISOString(), value);
      }
    }
  }

  handleChangeKeyword(event) {
    this.setState({ keyword: event.target.value });
  }

  renderFilters() {
    const {
      t,
      classes,
      availableFilterKeys,
      currentFilters,
      variant,
    } = this.props;
    const { entities, keyword } = this.state;
    return (
      <Grid container={true} spacing={2}>
        {variant === 'dialog' && (
          <Grid item={true} xs={12}>
            <TextField
              label={t('Global keyword')}
              variant="outlined"
              size="small"
              fullWidth={true}
              value={keyword}
              onChange={this.handleChangeKeyword.bind(this)}
            />
          </Grid>
        )}
        {filter((n) => !includes(n, directFilters), availableFilterKeys).map(
          (filterKey) => {
            const currentValue = currentFilters[filterKey]
              ? currentFilters[filterKey][0]
              : null;
            if (
              filterKey.endsWith('start_date')
              || filterKey.endsWith('end_date')
            ) {
              return (
                <Grid key={filterKey} item={true} xs={6}>
                  <KeyboardDatePicker
                    label={t(`filter_${filterKey}`)}
                    value={currentValue ? currentValue.id : null}
                    variant="inline"
                    disableToolbar={false}
                    autoOk={true}
                    allowKeyboardControl={true}
                    format="YYYY-MM-DD"
                    inputVariant="outlined"
                    size="small"
                    onChange={this.handleChangeDate.bind(this, filterKey)}
                  />
                </Grid>
              );
            }
            return (
              <Grid key={filterKey} item={true} xs={6}>
                <Autocomplete
                  selectOnFocus={true}
                  autoSelect={false}
                  autoHighlight={true}
                  getOptionLabel={(option) => (option.label ? option.label : '')
                  }
                  noOptionsText={t('No available options')}
                  options={entities[filterKey] ? entities[filterKey] : []}
                  onInputChange={this.searchEntities.bind(this, filterKey)}
                  onChange={this.handleChange.bind(this, filterKey)}
                  getOptionSelected={(option, value) => option.value === value}
                  renderInput={(params) => (
                    <TextField
                      {...params}
                      label={t(`filter_${filterKey}`)}
                      variant="outlined"
                      size="small"
                      fullWidth={true}
                      onFocus={this.searchEntities.bind(this, filterKey)}
                    />
                  )}
                  renderOption={(option) => (
                    <React.Fragment>
                      <div
                        className={classes.icon}
                        style={{ color: option.color }}
                      >
                        <ItemIcon type={option.type} />
                      </div>
                      <div className={classes.text}>{option.label}</div>
                    </React.Fragment>
                  )}
                />
              </Grid>
            );
          },
        )}
      </Grid>
    );
  }

  renderListFilters() {
    const { t, classes, availableFilterKeys } = this.props;
    const { open, anchorEl, entities } = this.state;
    return (
      <div className={classes.filters}>
        <IconButton
          color="primary"
          onClick={this.handleOpenFilters.bind(this)}
          style={{ float: 'left' }}
        >
          <FilterListOutlined />
        </IconButton>
        <Popover
          classes={{ paper: classes.container }}
          open={open}
          anchorEl={anchorEl}
          onClose={this.handleCloseFilters.bind(this)}
          anchorOrigin={{
            vertical: 'bottom',
            horizontal: 'center',
          }}
          transformOrigin={{
            vertical: 'top',
            horizontal: 'center',
          }}
        >
          {this.renderFilters()}
        </Popover>
        {filter((n) => includes(n, directFilters), availableFilterKeys).map(
          (filterKey) => (
            <Autocomplete
              key={filterKey}
              className={classes.autocomplete}
              selectOnFocus={true}
              autoSelect={false}
              autoHighlight={true}
              getOptionLabel={(option) => (option.label ? option.label : '')}
              noOptionsText={t('No available options')}
              options={entities[filterKey] ? entities[filterKey] : []}
              onInputChange={this.searchEntities.bind(this, filterKey)}
              onChange={this.handleChange.bind(this, filterKey)}
              getOptionSelected={(option, value) => option.value === value}
              renderInput={(params) => (
                <TextField
                  {...params}
                  label={t(`filter_${filterKey}`)}
                  variant="outlined"
                  size="small"
                  fullWidth={true}
                  onFocus={this.searchEntities.bind(this, filterKey)}
                />
              )}
              renderOption={(option) => (
                <React.Fragment>
                  <div className={classes.icon} style={{ color: option.color }}>
                    <ItemIcon type={option.type} />
                  </div>
                  <div className={classes.text}>{option.label}</div>
                </React.Fragment>
              )}
            />
          ),
        )}
        <div className="clearfix" />
      </div>
    );
  }

  handleAddFilter(key, id, value, event = null) {
    if (event) {
      event.stopPropagation();
      event.preventDefault();
    }
    if (this.state.filters[key] && this.state.filters[key].length > 0) {
      this.setState({
        filters: assoc(
          key,
          uniqBy(prop('id'), [{ id, value }, ...this.state.filters[key]]),
          this.state.filters,
        ),
      });
    } else {
      this.setState({
        filters: assoc(key, [{ id, value }], this.state.filters),
      });
    }
  }

  handleRemoveFilter(key) {
    this.setState({ filters: dissoc(key, this.state.filters) });
  }

  handleSearch() {
    this.handleCloseFilters();
    const urlParams = { filters: JSON.stringify(this.state.filters) };
    this.props.history.push(
      `/dashboard/search${
        this.state.keyword.length > 0 ? `/${this.state.keyword}` : ''
      }?${new URLSearchParams(urlParams).toString()}`,
    );
  }

  renderDialogFilters() {
    const { t, classes, disabled } = this.props;
    const { open, filters } = this.state;
    return (
      <div style={{ float: 'left' }}>
        <Tooltip title={t('Advanced search')}>
          <IconButton
            onClick={this.handleOpenFilters.bind(this)}
            disabled={disabled}
          >
            <ToyBrickSearchOutline fontSize="default" />
          </IconButton>
        </Tooltip>
        <Dialog
          open={open}
          onClose={this.handleCloseFilters.bind(this)}
          fullWidth={true}
          maxWidth="md"
        >
          <DialogTitle>{t('Advanced search')}</DialogTitle>
          <DialogContent>
            {filters && !isEmpty(filters) && (
              <div className={classes.filtersDialog}>
                {map((currentFilter) => {
                  const label = `${truncate(
                    t(`filter_${currentFilter[0]}`),
                    20,
                  )}`;
                  const values = (
                    <span>
                      {map(
                        (n) => (
                          <span key={n.value}>
                            {truncate(n.value, 15)}{' '}
                            {last(currentFilter[1]).value !== n.value && (
                              <code>OR</code>
                            )}
                          </span>
                        ),
                        currentFilter[1],
                      )}
                    </span>
                  );
                  return (
                    <span>
                      <Chip
                        key={currentFilter[0]}
                        classes={{ root: classes.filter }}
                        label={
                          <div>
                            {label}: {values}
                          </div>
                        }
                        onDelete={this.handleRemoveFilter.bind(
                          this,
                          currentFilter[0],
                        )}
                      />
                      {last(toPairs(filters))[0] !== currentFilter[0] && (
                        <Chip
                          classes={{ root: classes.operator }}
                          label={t('AND')}
                        />
                      )}
                    </span>
                  );
                }, toPairs(filters))}
              </div>
            )}
            {this.renderFilters()}
          </DialogContent>
          <DialogActions>
            <Button
              onClick={this.handleCloseFilters.bind(this)}
              classes={{ root: classes.button }}
            >
              {t('Cancel')}
            </Button>
            <Button
              color="primary"
              onClick={this.handleSearch.bind(this)}
              classes={{ root: classes.button }}
            >
              {t('Search')}
            </Button>
          </DialogActions>
        </Dialog>
      </div>
    );
  }

  render() {
    if (this.props.variant === 'dialog') {
      return this.renderDialogFilters();
    }
    return this.renderListFilters();
  }
}

Filters.propTypes = {
  classes: PropTypes.object,
  t: PropTypes.func,
  availableFilterKeys: PropTypes.array,
  handleAddFilter: PropTypes.func,
  currentFilters: PropTypes.object,
  variant: PropTypes.string,
  disabled: PropTypes.bool,
};

export default compose(inject18n, withRouter, withStyles(styles))(Filters);
