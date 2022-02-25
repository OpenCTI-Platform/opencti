import React, { Component } from 'react';
import * as R from 'ramda';
import withStyles from '@mui/styles/withStyles';
import withTheme from '@mui/styles/withTheme';
import Grid from '@mui/material/Grid';
import DatePicker from '@mui/lab/DatePicker';
import Autocomplete from '@mui/material/Autocomplete';
import TextField from '@mui/material/TextField';
import Popover from '@mui/material/Popover';
import IconButton from '@mui/material/IconButton';
import { FilterListOutlined } from '@mui/icons-material';
import * as PropTypes from 'prop-types';
import Tooltip from '@mui/material/Tooltip';
import { ToyBrickSearchOutline } from 'mdi-material-ui';
import DialogTitle from '@mui/material/DialogTitle';
import DialogContent from '@mui/material/DialogContent';
import Dialog from '@mui/material/Dialog';
import Chip from '@mui/material/Chip';
import { withRouter } from 'react-router-dom';
import DialogActions from '@mui/material/DialogActions';
import Button from '@mui/material/Button';
import { fetchQuery } from '../../../../relay/environment';
import inject18n from '../../../../components/i18n';
import { identitySearchIdentitiesSearchQuery } from '../identities/IdentitySearch';
import { labelsSearchQuery } from '../../settings/LabelsQuery';
import { attributesSearchQuery } from '../../settings/AttributesQuery';
import { markingDefinitionsLinesSearchQuery } from '../../settings/marking_definitions/MarkingDefinitionsLines';
import ItemIcon from '../../../../components/ItemIcon';
import { truncate } from '../../../../utils/String';
import { stixDomainObjectsLinesSearchQuery } from '../stix_domain_objects/StixDomainObjectsLines';
import { statusFieldStatusesSearchQuery } from '../form/StatusField';

const styles = (theme) => ({
  filters: {
    float: 'left',
    margin: '-3px 0 0 -5px',
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
  filter: {
    margin: '0 10px 10px 0',
  },
  operator: {
    fontFamily: 'Consolas, monaco, monospace',
    backgroundColor: theme.palette.background.paper,
    margin: '0 10px 10px 0',
  },
});

const directFilters = [
  'report_types',
  'sightedBy',
  'container_type',
  'toSightingId',
];
const uniqFilters = [
  'revoked',
  'x_opencti_detection',
  'x_opencti_base_score_gt',
  'confidence_gt',
  'x_opencti_score_gt',
  'x_opencti_score_lte',
  'toSightingId',
  'basedOn',
];
export const isUniqFilter = (key) => uniqFilters.includes(key)
  || key.endsWith('start_date')
  || key.endsWith('end_date');

class Filters extends Component {
  constructor(props) {
    super(props);
    this.state = {
      open: false,
      anchorEl: null,
      entities: {},
      filters: {},
      keyword: '',
      inputValues: {},
    };
  }

  handleOpenFilters(event) {
    this.setState({ open: true, anchorEl: event.currentTarget });
  }

  handleCloseFilters() {
    this.setState({ open: false, anchorEl: null });
  }

  searchEntities(filterKey, event) {
    const { t, theme } = this.props;
    if (event && event.target.value !== 0) {
      this.setState({
        inputValues: R.assoc(
          filterKey,
          event.target.value,
          this.state.inputValues,
        ),
      });
    }
    switch (filterKey) {
      case 'toSightingId':
        fetchQuery(identitySearchIdentitiesSearchQuery, {
          types: ['Identity'],
          search: event && event.target.value !== 0 ? event.target.value : '',
          first: 10,
        })
          .toPromise()
          .then((data) => {
            const createdByEntities = R.pipe(
              R.pathOr([], ['identities', 'edges']),
              R.map((n) => ({
                label: n.node.name,
                value: n.node.id,
                type: n.node.entity_type,
              })),
            )(data);
            this.setState({
              entities: {
                ...this.state.entities,
                toSightingId: R.union(
                  createdByEntities,
                  this.state.entities.toSightingId,
                ),
              },
            });
          });
        break;
      case 'createdBy':
        fetchQuery(identitySearchIdentitiesSearchQuery, {
          types: ['Organization', 'Individual', 'System'],
          search: event && event.target.value !== 0 ? event.target.value : '',
          first: 10,
        })
          .toPromise()
          .then((data) => {
            const createdByEntities = R.pipe(
              R.pathOr([], ['identities', 'edges']),
              R.map((n) => ({
                label: n.node.name,
                value: n.node.id,
                type: n.node.entity_type,
              })),
            )(data);
            this.setState({
              entities: {
                ...this.state.entities,
                createdBy: R.union(
                  createdByEntities,
                  this.state.entities.createdBy,
                ),
              },
            });
          });
        break;
      case 'sightedBy':
        fetchQuery(stixDomainObjectsLinesSearchQuery, {
          types: [
            'Sector',
            'Organization',
            'Individual',
            'Region',
            'Country',
            'City',
          ],
          search: event && event.target.value !== 0 ? event.target.value : '',
          count: 10,
        })
          .toPromise()
          .then((data) => {
            const sightedByEntities = R.pipe(
              R.pathOr([], ['stixDomainObjects', 'edges']),
              R.map((n) => ({
                label: n.node.name,
                value: n.node.id,
                type: n.node.entity_type,
              })),
            )(data);
            this.setState({
              entities: {
                ...this.state.entities,
                sightedBy: R.union(
                  sightedByEntities,
                  this.state.entities.sightedBy,
                ),
              },
            });
          });
        break;
      case 'markedBy':
        fetchQuery(markingDefinitionsLinesSearchQuery, {
          search: event && event.target.value !== 0 ? event.target.value : '',
          first: 10,
        })
          .toPromise()
          .then((data) => {
            const markedByEntities = R.pipe(
              R.pathOr([], ['markingDefinitions', 'edges']),
              R.map((n) => ({
                label: n.node.definition,
                value: n.node.id,
                type: 'Marking-Definition',
                color: n.node.x_opencti_color,
              })),
            )(data);
            this.setState({
              entities: {
                ...this.state.entities,
                markedBy: R.union(
                  markedByEntities,
                  this.state.entities.markedBy,
                ),
              },
            });
          });
        break;
      case 'labelledBy':
        fetchQuery(labelsSearchQuery, {
          search: event && event.target.value !== 0 ? event.target.value : '',
          first: 10,
        })
          .toPromise()
          .then((data) => {
            const labelledByEntities = R.pipe(
              R.pathOr([], ['labels', 'edges']),
              R.map((n) => ({
                label: n.node.value,
                value: n.node.id,
                type: 'Label',
                color: n.node.color,
              })),
            )(data);
            this.setState({
              entities: {
                ...this.state.entities,
                labelledBy: [
                  {
                    label: t('No label'),
                    value: null,
                    type: 'Label',
                    color:
                      theme.palette.mode === 'dark' ? '#ffffff' : '#000000',
                  },
                  ...R.union(
                    labelledByEntities,
                    this.state.entities.labelledBy,
                  ),
                ],
              },
            });
          });
        break;
      case 'x_opencti_base_score_gt':
        // eslint-disable-next-line no-case-declarations
        const baseScoreEntities = R.pipe(
          R.map((n) => ({
            label: n,
            value: n,
            type: 'attribute',
          })),
        )(['1', '2', '3', '4', '5', '6', '7', '8', '9']);
        this.setState({
          entities: {
            ...this.state.entities,
            x_opencti_base_score_gt: R.union(
              baseScoreEntities,
              this.state.entities.x_opencti_base_score_gt,
            ),
          },
        });
        break;
      case 'confidence_gt':
        // eslint-disable-next-line no-case-declarations
        const confidenceEntities = R.pipe(
          R.map((n) => ({
            label: t(`confidence_${n.toString()}`),
            value: n,
            type: 'attribute',
          })),
        )(['0', '15', '50', '75', '85']);
        this.setState({
          entities: {
            ...this.state.entities,
            confidence_gt: R.union(
              confidenceEntities,
              this.state.entities.confidence_gt,
            ),
          },
        });
        break;
      case 'x_opencti_score_gt':
        // eslint-disable-next-line no-case-declarations
        const scoreEntities = R.pipe(
          R.map((n) => ({
            label: n,
            value: n,
            type: 'attribute',
          })),
        )(['0', '10', '20', '30', '40', '50', '60', '70', '80', '90', '100']);
        this.setState({
          entities: {
            ...this.state.entities,
            x_opencti_score_gt: R.union(
              scoreEntities,
              this.state.entities.x_opencti_score_gt,
            ),
          },
        });
        break;
      case 'x_opencti_score_lte':
        // eslint-disable-next-line no-case-declarations
        const scoreLteEntities = R.pipe(
          R.map((n) => ({
            label: n,
            value: n,
            type: 'attribute',
          })),
        )(['0', '10', '20', '30', '40', '50', '60', '70', '80', '90', '100']);
        this.setState({
          entities: {
            ...this.state.entities,
            x_opencti_score_lte: R.union(
              scoreLteEntities,
              this.state.entities.x_opencti_score_lte,
            ),
          },
        });
        break;
      case 'x_opencti_detection':
        // eslint-disable-next-line no-case-declarations
        const detectionEntities = R.pipe(
          R.map((n) => ({
            label: t(n),
            value: n,
            type: 'attribute',
          })),
        )(['true', 'false']);
        this.setState({
          entities: {
            ...this.state.entities,
            x_opencti_detection: R.union(
              detectionEntities,
              this.state.entities.x_opencti_detection,
            ),
          },
        });
        break;
      case 'basedOn':
        // eslint-disable-next-line no-case-declarations
        const basedOnEntities = R.pipe(
          R.map((n) => ({
            label: n === 'EXISTS' ? t('Yes') : t('No'),
            value: n,
            type: 'attribute',
          })),
        )(['EXISTS', null]);
        this.setState({
          entities: {
            ...this.state.entities,
            basedOn: R.union(basedOnEntities, this.state.entities.basedOn),
          },
        });
        break;
      case 'revoked':
        // eslint-disable-next-line no-case-declarations
        const revokedEntities = R.pipe(
          R.map((n) => ({
            label: t(n),
            value: n,
            type: 'attribute',
          })),
        )(['true', 'false']);
        this.setState({
          entities: {
            ...this.state.entities,
            revoked: R.union(revokedEntities, this.state.entities.revoked),
          },
        });
        break;
      case 'pattern_type':
        // eslint-disable-next-line no-case-declarations
        const patternTypesEntities = R.pipe(
          R.map((n) => ({
            label: t(n),
            value: n,
            type: 'attribute',
          })),
        )([
          'stix',
          'pcre',
          'sigma',
          'snort',
          'suricata',
          'yara',
          'tanium-signal',
        ]);
        this.setState({
          entities: {
            ...this.state.entities,
            pattern_type: R.union(
              patternTypesEntities,
              this.state.entities.pattern_type,
            ),
          },
        });
        break;
      case 'x_opencti_base_severity':
        fetchQuery(attributesSearchQuery, {
          attributeName: 'x_opencti_base_severity',
          search: event && event.target.value !== 0 ? event.target.value : '',
          first: 10,
        })
          .toPromise()
          .then((data) => {
            const severityEntities = R.pipe(
              R.pathOr([], ['runtimeAttributes', 'edges']),
              R.map((n) => ({
                label: n.node.value,
                value: n.node.value,
                type: 'attribute',
              })),
            )(data);
            this.setState({
              entities: {
                ...this.state.entities,
                x_opencti_base_severity: R.union(
                  severityEntities,
                  this.state.entities.x_opencti_base_severity,
                ),
              },
            });
          });
        break;
      case 'x_opencti_attack_vector':
        fetchQuery(attributesSearchQuery, {
          attributeName: 'x_opencti_attack_vector',
          search: event && event.target.value !== 0 ? event.target.value : '',
          first: 10,
        })
          .toPromise()
          .then((data) => {
            const attackVectorEntities = R.pipe(
              R.pathOr([], ['runtimeAttributes', 'edges']),
              R.map((n) => ({
                label: n.node.value,
                value: n.node.value,
                type: 'attribute',
              })),
            )(data);
            this.setState({
              entities: {
                ...this.state.entities,
                x_opencti_attack_vector: R.union(
                  attackVectorEntities,
                  this.state.entities.x_opencti_attack_vector,
                ),
              },
            });
          });
        break;
      case 'status_id':
        fetchQuery(statusFieldStatusesSearchQuery, {
          search: event && event.target.value !== 0 ? event.target.value : '',
          first: 50,
        })
          .toPromise()
          .then((data) => {
            const statusEntities = R.pipe(
              R.pathOr([], ['statuses', 'edges']),
              R.map((n) => ({
                label: t(`status_${n.node.template.name}`),
                color: n.node.template.color,
                value: n.node.id,
                order: n.node.order,
                type: 'attribute',
              })),
            )(data);
            this.setState({
              entities: {
                ...this.state.entities,
                status_id: R.union(
                  statusEntities,
                  this.state.entities.status_id,
                ),
              },
            });
          });
        break;
      case 'x_opencti_organization_type':
        fetchQuery(attributesSearchQuery, {
          attributeName: 'x_opencti_organization_type',
          search: event && event.target.value !== 0 ? event.target.value : '',
          first: 10,
        })
          .toPromise()
          .then((data) => {
            const organizationTypeEntities = R.pipe(
              R.pathOr([], ['runtimeAttributes', 'edges']),
              R.map((n) => ({
                label: n.node.value,
                value: n.node.value,
                type: 'attribute',
              })),
            )(data);
            this.setState({
              entities: {
                ...this.state.entities,
                x_opencti_organization_type: R.union(
                  organizationTypeEntities,
                  this.state.entities.x_opencti_organization_type,
                ),
              },
            });
          });
        break;
      case 'report_types':
        fetchQuery(attributesSearchQuery, {
          attributeName: 'report_types',
          search: event && event.target.value !== 0 ? event.target.value : '',
          first: 10,
        })
          .toPromise()
          .then((data) => {
            const reportTypesEntities = R.pipe(
              R.pathOr([], ['runtimeAttributes', 'edges']),
              R.map((n) => ({
                label: t(n.node.value),
                value: n.node.value,
                type: 'attribute',
              })),
            )(data);
            this.setState({
              entities: {
                ...this.state.entities,
                report_types: R.union(
                  reportTypesEntities,
                  this.state.entities.report_types,
                ),
              },
            });
          });
        break;
      case 'entity_type':
        // eslint-disable-next-line no-case-declarations
        // eslint-disable-next-line no-case-declarations
        let entitiesTypes = R.pipe(
          R.map((n) => ({
            label: t(
              n.toString()[0] === n.toString()[0].toUpperCase()
                ? `entity_${n.toString()}`
                : `relationship_${n.toString()}`,
            ),
            value: n,
            type: n,
          })),
          R.sortWith([R.ascend(R.prop('label'))]),
        )([
          'Attack-Pattern',
          'Campaign',
          'Note',
          'Observed-Data',
          'Opinion',
          'Report',
          'Course-Of-Action',
          'Individual',
          'Organization',
          'Sector',
          'Indicator',
          'Infrastructure',
          'Intrusion-Set',
          'City',
          'Country',
          'Region',
          'Position',
          'Malware',
          'Threat-Actor',
          'Tool',
          'Vulnerability',
          'Incident',
          'Stix-Cyber-Observable',
          'Stix-Core-Relationship',
          'indicates',
          'targets',
          'uses',
          'located-at',
        ]);
        if (this.props.allEntityTypes) {
          entitiesTypes = R.prepend(
            { label: t('entity_All'), value: 'all', type: 'entity' },
            entitiesTypes,
          );
        }
        this.setState({
          entities: {
            ...this.state.entities,
            entity_type: R.union(
              entitiesTypes,
              this.state.entities.entity_type,
            ),
          },
        });
        break;
      case 'container_type':
        // eslint-disable-next-line no-case-declarations
        const containersTypes = R.pipe(
          R.map((n) => ({
            label: t(
              n.toString()[0] === n.toString()[0].toUpperCase()
                ? `entity_${n.toString()}`
                : `relationship_${n.toString()}`,
            ),
            value: n,
            type: n,
          })),
          R.sortWith([R.ascend(R.prop('label'))]),
        )(['Note', 'Observed-Data', 'Opinion', 'Report']);
        this.setState({
          entities: {
            ...this.state.entities,
            container_type: R.union(
              containersTypes,
              this.state.entities.container_type,
            ),
          },
        });
        break;
      default:
        this.setState({ entities: R.union(this.state.entities, []) });
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
      noDirectFilters,
    } = this.props;
    const { entities, keyword, inputValues } = this.state;
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
        {R.filter(
          (n) => noDirectFilters || !R.includes(n, directFilters),
          availableFilterKeys,
        ).map((filterKey) => {
          const currentValue = currentFilters[filterKey]
            ? currentFilters[filterKey][0]
            : null;
          if (
            filterKey.endsWith('start_date')
            || filterKey.endsWith('end_date')
          ) {
            return (
              <Grid key={filterKey} item={true} xs={6}>
                <DatePicker
                  label={t(`filter_${filterKey}`)}
                  value={currentValue ? currentValue.id : null}
                  variant="inline"
                  disableToolbar={false}
                  autoOk={true}
                  allowKeyboardControl={true}
                  format="YYYY-MM-DD"
                  onChange={this.handleChangeDate.bind(this, filterKey)}
                  renderInput={(params) => (
                    <TextField
                      variant="outlined"
                      size="small"
                      fullWidth={variant === 'dialog'}
                      {...params}
                    />
                  )}
                />
              </Grid>
            );
          }
          return (
            <Grid key={filterKey} item={true} xs={6}>
              <Autocomplete
                selectOnFocus={true}
                openOnFocus={true}
                autoSelect={false}
                autoHighlight={true}
                getOptionLabel={(option) => (option.label ? option.label : '')}
                noOptionsText={t('No available options')}
                options={entities[filterKey] ? entities[filterKey] : []}
                onInputChange={this.searchEntities.bind(this, filterKey)}
                inputValue={inputValues[filterKey] || ''}
                onChange={this.handleChange.bind(this, filterKey)}
                isOptionEqualToValue={(option, value) => option.value === value.value
                }
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
                renderOption={(props, option) => (
                  <li {...props}>
                    <div
                      className={classes.icon}
                      style={{ color: option.color }}
                    >
                      <ItemIcon type={option.type} />
                    </div>
                    <div className={classes.text}>{option.label}</div>
                  </li>
                )}
              />
            </Grid>
          );
        })}
      </Grid>
    );
  }

  renderListFilters() {
    const { t, classes, availableFilterKeys, noDirectFilters } = this.props;
    const { open, anchorEl, entities, inputValues } = this.state;
    return (
      <div className={classes.filters}>
        {this.props.variant === 'text' ? (
          <Button
            variant="contained"
            color="primary"
            onClick={this.handleOpenFilters.bind(this)}
            startIcon={<FilterListOutlined />}
            size="small"
            style={{ float: 'left', margin: '0 15px 0 7px' }}
          >
            {t('Filters')}
          </Button>
        ) : (
          <IconButton
            color="primary"
            onClick={this.handleOpenFilters.bind(this)}
            style={{ float: 'left', marginTop: -2 }}
            size="large"
          >
            <FilterListOutlined />
          </IconButton>
        )}
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
        {!noDirectFilters
          && R.filter(
            (n) => R.includes(n, directFilters),
            availableFilterKeys,
          ).map((filterKey) => (
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
              isOptionEqualToValue={(option, value) => option.value === value}
              inputValue={inputValues[filterKey] || ''}
              renderInput={(params) => (
                <TextField
                  {...params}
                  name={filterKey}
                  label={t(`filter_${filterKey}`)}
                  variant="outlined"
                  size="small"
                  fullWidth={true}
                  onFocus={this.searchEntities.bind(this, filterKey)}
                />
              )}
              renderOption={(props, option) => (
                <li {...props}>
                  <div className={classes.icon} style={{ color: option.color }}>
                    <ItemIcon type={option.type} />
                  </div>
                  <div className={classes.text}>{option.label}</div>
                </li>
              )}
            />
          ))}
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
        filters: R.assoc(
          key,
          isUniqFilter(key)
            ? [{ id, value }]
            : R.uniqBy(R.prop('id'), [
              { id, value },
              ...this.state.filters[key],
            ]),
          this.state.filters,
        ),
      });
    } else {
      this.setState({
        filters: R.assoc(key, [{ id, value }], this.state.filters),
      });
    }
  }

  handleRemoveFilter(key) {
    this.setState({ filters: R.dissoc(key, this.state.filters) });
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
      <React.Fragment>
        <Tooltip title={t('Advanced search')}>
          <IconButton
            onClick={this.handleOpenFilters.bind(this)}
            disabled={disabled}
            size="medium"
          >
            <ToyBrickSearchOutline fontSize="medium" />
          </IconButton>
        </Tooltip>
        <Dialog
          PaperProps={{ elevation: 1 }}
          open={open}
          onClose={this.handleCloseFilters.bind(this)}
          fullWidth={true}
          maxWidth="md"
        >
          <DialogTitle>{t('Advanced search')}</DialogTitle>
          <DialogContent style={{ paddingTop: 10 }}>
            {filters && !R.isEmpty(filters) && (
              <div className={classes.filtersDialog}>
                {R.map((currentFilter) => {
                  const label = `${truncate(
                    t(`filter_${currentFilter[0]}`),
                    20,
                  )}`;
                  const values = (
                    <span>
                      {R.map(
                        (n) => (
                          <span key={n.value}>
                            {truncate(n.value, 15)}{' '}
                            {R.last(currentFilter[1]).value !== n.value && (
                              <code style={{ marginRight: 5 }}>OR</code>
                            )}
                          </span>
                        ),
                        currentFilter[1],
                      )}
                    </span>
                  );
                  return (
                    <span key={currentFilter[0]}>
                      <Chip
                        classes={{ root: classes.filter }}
                        label={
                          <div>
                            <strong>{label}</strong>: {values}
                          </div>
                        }
                        onDelete={this.handleRemoveFilter.bind(
                          this,
                          currentFilter[0],
                        )}
                      />
                      {R.last(R.toPairs(filters))[0] !== currentFilter[0] && (
                        <Chip
                          classes={{ root: classes.operator }}
                          label={t('AND')}
                        />
                      )}
                    </span>
                  );
                }, R.toPairs(filters))}
              </div>
            )}
            {this.renderFilters()}
          </DialogContent>
          <DialogActions>
            <Button
              variant="contained"
              onClick={this.handleCloseFilters.bind(this)}
              color="secondary"
            >
              {t('Cancel')}
            </Button>
            <Button variant="contained" onClick={this.handleSearch.bind(this)}>
              {t('Search')}
            </Button>
          </DialogActions>
        </Dialog>
      </React.Fragment>
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
  theme: PropTypes.object,
  t: PropTypes.func,
  availableFilterKeys: PropTypes.array,
  handleAddFilter: PropTypes.func,
  currentFilters: PropTypes.object,
  variant: PropTypes.string,
  disabled: PropTypes.bool,
  noDirectFilters: PropTypes.bool,
  allEntityTypes: PropTypes.bool,
};

export default R.compose(
  inject18n,
  withRouter,
  withTheme,
  withStyles(styles),
)(Filters);
