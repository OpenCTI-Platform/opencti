import React, { Component } from 'react';
import * as R from 'ramda';
import { withStyles, withTheme } from '@material-ui/core/styles';
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
import {
  itAssetFiltersAssetTypeFieldQuery,
  itAssetFiltersDeviceFieldsQuery,
  itAssetFiltersNetworkFieldsQuery,
  itAssetFiltersSoftwareFieldsQuery,
} from '../../settings/ItAssetFilters';
import { RiskFiltersQuery, riskFiltersNameQuery } from '../../settings/RiskFilters';
import { attributesSearchQuery } from '../../settings/AttributesQuery';
import { markingDefinitionsLinesSearchQuery } from '../../settings/marking_definitions/MarkingDefinitionsLines';
import ItemIcon from '../../../../components/ItemIcon';
import { truncate } from '../../../../utils/String';
import { stixDomainObjectsLinesSearchQuery } from '../stix_domain_objects/StixDomainObjectsLines';
import { statusFieldStatusesSearchQuery } from '../form/StatusField';
import { fetchDarklightQuery } from '../../../../relay/environmentDarkLight';
import { dateFormatRegex } from '../../../../utils/Network';

const styles = (theme) => ({
  filters: {
    float: 'left',
    margin: '-10px 0 0 -5px',
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
    margin: '0 10px 10px 0',
  },
  operator: {
    fontFamily: 'Consolas, monaco, monospace',
    backgroundColor: theme.palette.background.chip,
    margin: '0 10px 10px 0',
  },
});

const directFilters = [
  'report_types',
  'x_opencti_detection',
  'sightedBy',
  'container_type',
  'toSightingId',
];
const uniqFilters = [
  'name_m',
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
      case 'asset_type_or':
        fetchDarklightQuery(itAssetFiltersAssetTypeFieldQuery, {
          type: `${this.props.filterEntityType}AssetTypes`,
          search: event && event.target.value !== 0 ? event.target.value : '',
        })
          .toPromise()
          .then((data) => {
            const assetTypeEntities = R.pipe(
              R.pathOr([], ['__type', 'enumValues']),
              R.map((n) => ({
                label: t(n.description),
                value: n.name,
                type: n.name,
              })),
            )(data);
            this.setState({
              entities: {
                ...this.state.entities,
                asset_type_or: R.union(
                  assetTypeEntities,
                  this.state.entities.asset_type,
                ),
              },
            });
          });
        break;
      case 'name_m':
        // eslint-disable-next-line no-case-declarations
        let nameQuery = '';
        // eslint-disable-next-line no-case-declarations
        let namePath = [];
        if (this.props.filterEntityType === 'Device') {
          nameQuery = itAssetFiltersDeviceFieldsQuery;
          namePath = ['computingDeviceAssetList', 'edges'];
        }
        if (this.props.filterEntityType === 'Network') {
          nameQuery = itAssetFiltersNetworkFieldsQuery;
          namePath = ['networkAssetList', 'edges'];
        }
        if (this.props.filterEntityType === 'Software') {
          nameQuery = itAssetFiltersSoftwareFieldsQuery;
          namePath = ['softwareAssetList', 'edges'];
        }
        if (this.props.filterEntityType === 'Risk') {
          nameQuery = riskFiltersNameQuery;
          namePath = ['risks', 'edges'];
        }
        fetchDarklightQuery(nameQuery, {
          search: event && event.target.value !== 0 ? event.target.value : '',
        })
          .toPromise()
          .then((data) => {
            const nameEntities = R.pipe(
              R.pathOr([], namePath),
              R.map((n) => ({
                label: n.node.name,
                value: n.node.name,
                type: 'attribute',
              })),
            )(data);
            this.setState({
              entities: {
                ...this.state.entities,
                name_m: R.union(
                  nameEntities,
                  this.state.entities.name_m,
                ),
              },
            });
          });
        break;
      case 'risk_level':
        fetchDarklightQuery(RiskFiltersQuery, {
          type: 'RiskLevel',
        })
          .toPromise()
          .then((data) => {
            const riskLevelEntities = R.pipe(
              R.pathOr([], ['__type', 'enumValues']),
              R.map((n) => ({
                label: t(n.name),
                value: n.name,
                type: 'attribute',
              })),
            )(data);
            this.setState({
              entities: {
                ...this.state.entities,
                risk_level: R.union(
                  riskLevelEntities,
                  this.state.entities.risk_level,
                ),
              },
            });
          });
        break;
      case 'risk_status':
        fetchDarklightQuery(RiskFiltersQuery, {
          type: 'RiskStatus',
        })
          .toPromise()
          .then((data) => {
            const riskStatusEntities = R.pipe(
              R.pathOr([], ['__type', 'enumValues']),
              R.map((n) => ({
                label: t(n.name),
                value: n.name,
                type: 'attribute',
              })),
            )(data);
            this.setState({
              entities: {
                ...this.state.entities,
                risk_status: R.union(
                  riskStatusEntities,
                  this.state.entities.risk_status,
                ),
              },
            });
          });
        break;
      case 'lifecycle':
        fetchDarklightQuery(RiskFiltersQuery, {
          type: 'RiskLifeCyclePhase',
        })
          .toPromise()
          .then((data) => {
            const riskLifecycleEntities = R.pipe(
              R.pathOr([], ['__type', 'enumValues']),
              R.map((n) => ({
                label: t(n.name),
                value: n.name,
                type: 'attribute',
              })),
            )(data);
            this.setState({
              entities: {
                ...this.state.entities,
                lifecycle: R.union(
                  riskLifecycleEntities,
                  this.state.entities.lifecycle,
                ),
              },
            });
          });
        break;
      case 'risk_response':
        fetchDarklightQuery(RiskFiltersQuery, {
          type: 'ResponseType',
        })
          .toPromise()
          .then((data) => {
            const riskResponseEntities = R.pipe(
              R.pathOr([], ['__type', 'enumValues']),
              R.map((n) => ({
                label: t(n.name),
                value: n.name,
                type: 'attribute',
              })),
            )(data);
            this.setState({
              entities: {
                ...this.state.entities,
                risk_response: R.union(
                  riskResponseEntities,
                  this.state.entities.risk_response,
                ),
              },
            });
          });
        break;
      case 'vendor_name_or':
        fetchDarklightQuery(itAssetFiltersSoftwareFieldsQuery, {
          search: event && event.target.value !== 0 ? event.target.value : '',
        })
          .toPromise()
          .then((data) => {
            const vendorEntities = R.pipe(
              R.pathOr([], ['softwareAssetList', 'edges']),
              R.map((n) => ({
                label: t(n.node.vendor_name),
                value: n.node.vendor_name,
                type: n.node.vendor_name === 'apple' || n.node.vendor_name === 'microsoft' || n.node.vendor_name === 'linux' ? n.node.vendor_name : 'other',
              })),
            )(data);
            this.setState({
              entities: {
                ...this.state.entities,
                vendor_name_or: R.union(
                  vendorEntities,
                  this.state.entities.vendor_name_or,
                ),
              },
            });
          });
        break;
      case 'label_name':
        // eslint-disable-next-line no-case-declarations
        fetchDarklightQuery(labelsSearchQuery, {
          search: event && event.target.value !== 0 ? event.target.value : '',
        })
          .toPromise()
          .then((data) => {
            const cyioLabelEntities = R.pipe(
              R.pathOr([], ['cyioLabels', 'edges']),
              R.map((n) => ({
                label: n.node?.name && t(n.node?.name),
                value: n.node?.name,
                type: 'Label',
                color: n.node?.color,
              })),
            )(data);
            this.setState({
              entities: {
                ...this.state.entities,
                label_name: R.union(
                  cyioLabelEntities,
                  this.state.entities.label_name,
                ),
              },
            });
          });
        break;
      case 'toSightingId':
        fetchQuery(identityCreationIdentitiesSearchQuery, {
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
        fetchQuery(identityCreationIdentitiesSearchQuery, {
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
              R.pathOr([], ['cyioLabels', 'edges']),
              R.map((n) => ({
                label: n.node.name,
                value: n.node.name,
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
                      theme.palette.type === 'dark' ? '#ffffff' : '#000000',
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
          fieldKey: 'x_opencti_base_severity',
          search: event && event.target.value !== 0 ? event.target.value : '',
          first: 10,
        })
          .toPromise()
          .then((data) => {
            const severityEntities = R.pipe(
              R.pathOr([], ['attributes', 'edges']),
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
          fieldKey: 'x_opencti_attack_vector',
          search: event && event.target.value !== 0 ? event.target.value : '',
          first: 10,
        })
          .toPromise()
          .then((data) => {
            const attackVectorEntities = R.pipe(
              R.pathOr([], ['attributes', 'edges']),
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
          fieldKey: 'x_opencti_organization_type',
          search: event && event.target.value !== 0 ? event.target.value : '',
          first: 10,
        })
          .toPromise()
          .then((data) => {
            const organizationTypeEntities = R.pipe(
              R.pathOr([], ['attributes', 'edges']),
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
          key: 'report_types',
          search: event && event.target.value !== 0 ? event.target.value : '',
          first: 10,
        })
          .toPromise()
          .then((data) => {
            const reportTypesEntities = R.pipe(
              R.pathOr([], ['attributes', 'edges']),
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
        const entitiesTypes = R.pipe(
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
    const newDate = date.toISOString().replace(dateFormatRegex, 'T00:00:00.000Z');
    if (date && value && date.toISOString()) {
      if (this.props.variant === 'dialog') {
        this.handleAddFilter(filterKey, newDate, value);
      } else {
        this.props.handleAddFilter(filterKey, newDate, value);
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
                  fullWidth={variant === 'dialog'}
                  onChange={this.handleChangeDate.bind(this, filterKey)}
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
                getOptionSelected={(option, value) => option.value === value.value
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
        })}
      </Grid>
    );
  }

  renderListFilters() {
    const {
      t, classes, availableFilterKeys, noDirectFilters,
    } = this.props;
    const {
      open, anchorEl, entities, inputValues,
    } = this.state;
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
          <Tooltip title={t('Filter')}>
            <IconButton
              color="primary"
              onClick={this.handleOpenFilters.bind(this)}
              style={{ float: 'left' }}
            >
              <FilterListOutlined />
            </IconButton>
          </Tooltip>
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
              getOptionSelected={(option, value) => option.value === value}
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
              renderOption={(option) => (
                <React.Fragment>
                  <div className={classes.icon} style={{ color: option.color }}>
                    <ItemIcon type={option.type} />
                  </div>
                  <div className={classes.text}>{option.label}</div>
                </React.Fragment>
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
      `/dashboard/search${this.state.keyword.length > 0 ? `/${this.state.keyword}` : ''
      }?${new URLSearchParams(urlParams).toString()}`,
    );
  }

  renderDialogFilters() {
    const {
      t, classes, theme, disabled,
    } = this.props;
    const { open, filters } = this.state;
    return (
      <div style={{ float: 'left' }}>
        <Tooltip title={t('Advanced search')}>
          <IconButton
            onClick={this.handleOpenFilters.bind(this)}
            disabled={disabled}
          // style={{ color: theme.palette.header.text }}
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
                              <code>OR</code>
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
  theme: PropTypes.object,
  t: PropTypes.func,
  availableFilterKeys: PropTypes.array,
  handleAddFilter: PropTypes.func,
  currentFilters: PropTypes.object,
  variant: PropTypes.string,
  disabled: PropTypes.bool,
  noDirectFilters: PropTypes.bool,
};

export default R.compose(
  inject18n,
  withRouter,
  withTheme,
  withStyles(styles),
)(Filters);
