import React, { Component } from 'react';
import * as R from 'ramda';
import withStyles from '@mui/styles/withStyles';
import withTheme from '@mui/styles/withTheme';
import Grid from '@mui/material/Grid';
import { DatePicker } from '@mui/x-date-pickers/DatePicker';
import Autocomplete from '@mui/material/Autocomplete';
import TextField from '@mui/material/TextField';
import Popover from '@mui/material/Popover';
import IconButton from '@mui/material/IconButton';
import InputAdornment from '@mui/material/InputAdornment';
import { FilterListOutlined, PaletteOutlined } from '@mui/icons-material';
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
import { graphql } from 'react-relay';
import Checkbox from '@mui/material/Checkbox';
import ListItemText from '@mui/material/ListItemText';
import MenuList from '@mui/material/MenuList';
import MenuItem from '@mui/material/MenuItem';
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
import { defaultValue } from '../../../../utils/Graph';

export const filtersAllTypesQuery = graphql`
  query FiltersAllTypesQuery {
    scoTypes: subTypes(type: "Stix-Cyber-Observable") {
      edges {
        node {
          id
          label
        }
      }
    }
    sdoTypes: subTypes(type: "Stix-Domain-Object") {
      edges {
        node {
          id
          label
        }
      }
    }
    sroTypes: subTypes(type: "stix-core-relationship") {
      edges {
        node {
          id
          label
        }
      }
    }
  }
`;

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
  container2: {
    width: 300,
    padding: 0,
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
  'fromId',
  'toId',
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

export const entityTypes = [
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
  'StixFile',
  'IPv4-Addr',
  'Domain-Name',
  'Email-Addr',
  'Email-Message',
];
export const relationTypes = [
  'Stix-Core-Relationship',
  'indicates',
  'targets',
  'uses',
  'located-at',
];
export const allEntityTypes = [...entityTypes, ...relationTypes];

export const isUniqFilter = (key) => uniqFilters.includes(key)
  || key.endsWith('start_date')
  || key.endsWith('end_date');

export const filtersStixCoreObjectsSearchQuery = graphql`
  query FiltersStixCoreObjectsSearchQuery(
    $search: String
    $types: [String]
    $count: Int
    $filters: [StixCoreObjectsFiltering]
  ) {
    stixCoreObjects(
      search: $search
      types: $types
      first: $count
      filters: $filters
    ) {
      edges {
        node {
          id
          entity_type
          ... on AttackPattern {
            name
            description
            x_mitre_id
          }
          ... on Note {
            attribute_abstract
            content
          }
          ... on ObservedData {
            first_observed
            last_observed
          }
          ... on Opinion {
            opinion
          }
          ... on Report {
            name
          }
          ... on Campaign {
            name
            description
          }
          ... on CourseOfAction {
            name
            description
          }
          ... on Individual {
            name
            description
          }
          ... on Organization {
            name
            description
          }
          ... on Sector {
            name
            description
          }
          ... on System {
            name
            description
          }
          ... on Indicator {
            name
            description
          }
          ... on Infrastructure {
            name
            description
          }
          ... on IntrusionSet {
            name
            description
          }
          ... on Position {
            name
            description
          }
          ... on City {
            name
            description
          }
          ... on Country {
            name
            description
          }
          ... on Region {
            name
            description
          }
          ... on Malware {
            name
            description
          }
          ... on ThreatActor {
            name
            description
          }
          ... on Tool {
            name
            description
          }
          ... on Vulnerability {
            name
            description
          }
          ... on Incident {
            name
            description
          }
          ... on Event {
            name
            description
          }
          ... on Channel {
            name
            description
          }
          ... on Narrative {
            name
            description
          }
          ... on Language {
            name
          }
          ... on StixCyberObservable {
            observable_value
          }
          createdBy {
            ... on Identity {
              id
              name
              entity_type
            }
          }
          objectMarking {
            edges {
              node {
                definition
              }
            }
          }
        }
      }
    }
  }
`;

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
      anchorElSearchScope: {},
      searchScope: {},
      openSearchScope: {},
    };
  }

  handleOpenFilters(event) {
    this.setState({ open: true, anchorEl: event.currentTarget });
  }

  handleCloseFilters() {
    this.setState({ open: false, anchorEl: null });
  }

  searchEntities(filterKey, event) {
    const { searchScope } = this.state;
    const { t, theme, availableEntityTypes, availableRelationshipTypes } = this.props;
    if (!event) {
      return;
    }
    if (event.target.value !== 0) {
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
          search: event.target.value !== 0 ? event.target.value : '',
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
          search: event.target.value !== 0 ? event.target.value : '',
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
          search: event.target.value !== 0 ? event.target.value : '',
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
      case 'fromId':
        fetchQuery(filtersStixCoreObjectsSearchQuery, {
          types: (searchScope && searchScope.fromId) || ['Stix-Core-Object'],
          search: event.target.value !== 0 ? event.target.value : '',
          count: 50,
        })
          .toPromise()
          .then((data) => {
            const fromIdEntities = R.pipe(
              R.pathOr([], ['stixCoreObjects', 'edges']),
              R.map((n) => ({
                label: defaultValue(n.node),
                value: n.node.id,
                type: n.node.entity_type,
              })),
            )(data);
            this.setState({
              entities: {
                ...this.state.entities,
                fromId: R.union(fromIdEntities, this.state.entities.fromId),
              },
            });
          });
        break;
      case 'toId':
        fetchQuery(filtersStixCoreObjectsSearchQuery, {
          types: (searchScope && searchScope.toId) || ['Stix-Core-Object'],
          search: event.target.value !== 0 ? event.target.value : '',
          count: 100,
        })
          .toPromise()
          .then((data) => {
            const toIdEntities = R.pipe(
              R.pathOr([], ['stixCoreObjects', 'edges']),
              R.map((n) => ({
                label: defaultValue(n.node),
                value: n.node.id,
                type: n.node.entity_type,
              })),
            )(data);
            this.setState({
              entities: {
                ...this.state.entities,
                toId: R.union(toIdEntities, this.state.entities.toId),
              },
            });
          });
        break;
      case 'markedBy':
        fetchQuery(markingDefinitionsLinesSearchQuery, {
          search: event.target.value !== 0 ? event.target.value : '',
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
          search: event.target.value !== 0 ? event.target.value : '',
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
          'spl',
          'eql',
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
          search: event.target.value !== 0 ? event.target.value : '',
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
          search: event.target.value !== 0 ? event.target.value : '',
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
      case 'x_opencti_workflow_id':
        fetchQuery(statusFieldStatusesSearchQuery, {
          search: event.target.value !== 0 ? event.target.value : '',
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
                x_opencti_workflow_id: R.uniqBy(
                  R.prop('value'),
                  R.union(
                    statusEntities,
                    this.state.entities.x_opencti_workflow_id,
                  ),
                ),
              },
            });
          });
        break;
      case 'x_opencti_organization_type':
        fetchQuery(attributesSearchQuery, {
          attributeName: 'x_opencti_organization_type',
          search: event.target.value !== 0 ? event.target.value : '',
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
          search: event.target.value !== 0 ? event.target.value : '',
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
        let entitiesTypes = [];
        if (
          availableEntityTypes
          && !availableEntityTypes.includes('Stix-Cyber-Observable')
          && !availableEntityTypes.includes('Stix-Domain-Object')
        ) {
          entitiesTypes = R.pipe(
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
          )(availableEntityTypes);
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
        } else {
          fetchQuery(filtersAllTypesQuery)
            .toPromise()
            .then((data) => {
              let result = [];
              if (
                !availableEntityTypes
                || availableEntityTypes.includes('Stix-Cyber-Observable')
              ) {
                result = [
                  ...R.pipe(
                    R.pathOr([], ['scoTypes', 'edges']),
                    R.map((n) => ({
                      label: t(`entity_${n.node.label}`),
                      value: n.node.label,
                      type: n.node.label,
                    })),
                  )(data),
                  ...result,
                ];
              }
              if (
                !availableEntityTypes
                || availableEntityTypes.includes('Stix-Domain-Object')
              ) {
                result = [
                  ...R.pipe(
                    R.pathOr([], ['sdoTypes', 'edges']),
                    R.map((n) => ({
                      label: t(`entity_${n.node.label}`),
                      value: n.node.label,
                      type: n.node.label,
                    })),
                  )(data),
                  ...result,
                ];
              }
              if (
                !availableEntityTypes
                || availableEntityTypes.includes('stix-core-relationship')
              ) {
                result = [
                  ...R.pipe(
                    R.pathOr([], ['sroTypes', 'edges']),
                    R.map((n) => ({
                      label: t(`relationship_${n.node.label}`),
                      value: n.node.label,
                      type: n.node.label,
                    })),
                  )(data),
                  ...result,
                ];
              }
              entitiesTypes = R.sortWith([R.ascend(R.prop('label'))], result);
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
            });
        }
        break;
      case 'fromTypes':
        // eslint-disable-next-line no-case-declarations
        let fromTypesTypes = [];
        if (
          availableEntityTypes
          && !availableEntityTypes.includes('Stix-Cyber-Observable')
          && !availableEntityTypes.includes('Stix-Domain-Object')
        ) {
          fromTypesTypes = R.pipe(
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
          )(availableEntityTypes);
          if (this.props.allEntityTypes) {
            fromTypesTypes = R.prepend(
              { label: t('entity_All'), value: 'all', type: 'entity' },
              fromTypesTypes,
            );
          }
          this.setState({
            entities: {
              ...this.state.entities,
              fromTypes: R.union(fromTypesTypes, this.state.entities.fromTypes),
            },
          });
        } else {
          fetchQuery(filtersAllTypesQuery)
            .toPromise()
            .then((data) => {
              let result = [];
              if (
                !availableEntityTypes
                || availableEntityTypes.includes('Stix-Cyber-Observable')
              ) {
                result = [
                  ...R.pipe(
                    R.pathOr([], ['scoTypes', 'edges']),
                    R.map((n) => ({
                      label: t(`entity_${n.node.label}`),
                      value: n.node.label,
                      type: n.node.label,
                    })),
                  )(data),
                  ...result,
                ];
              }
              if (
                !availableEntityTypes
                || availableEntityTypes.includes('Stix-Domain-Object')
              ) {
                result = [
                  ...R.pipe(
                    R.pathOr([], ['sdoTypes', 'edges']),
                    R.map((n) => ({
                      label: t(`entity_${n.node.label}`),
                      value: n.node.label,
                      type: n.node.label,
                    })),
                  )(data),
                  ...result,
                ];
              }
              fromTypesTypes = R.sortWith([R.ascend(R.prop('label'))], result);
              if (this.props.allEntityTypes) {
                fromTypesTypes = R.prepend(
                  { label: t('entity_All'), value: 'all', type: 'entity' },
                  fromTypesTypes,
                );
              }
              this.setState({
                entities: {
                  ...this.state.entities,
                  fromTypes: R.union(
                    fromTypesTypes,
                    this.state.entities.fromTypes,
                  ),
                },
              });
            });
        }
        break;
      case 'toTypes':
        // eslint-disable-next-line no-case-declarations
        let toTypesTypes = [];
        if (
          availableEntityTypes
          && !availableEntityTypes.includes('Stix-Cyber-Observable')
          && !availableEntityTypes.includes('Stix-Domain-Object')
        ) {
          toTypesTypes = R.pipe(
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
          )(availableEntityTypes);
          if (this.props.allEntityTypes) {
            toTypesTypes = R.prepend(
              { label: t('entity_All'), value: 'all', type: 'entity' },
              toTypesTypes,
            );
          }
          this.setState({
            entities: {
              ...this.state.entities,
              toTypes: R.union(toTypesTypes, this.state.entities.toTypes),
            },
          });
        } else {
          fetchQuery(filtersAllTypesQuery)
            .toPromise()
            .then((data) => {
              let result = [];
              if (
                !availableEntityTypes
                || availableEntityTypes.includes('Stix-Cyber-Observable')
              ) {
                result = [
                  ...R.pipe(
                    R.pathOr([], ['scoTypes', 'edges']),
                    R.map((n) => ({
                      label: t(`entity_${n.node.label}`),
                      value: n.node.label,
                      type: n.node.label,
                    })),
                  )(data),
                  ...result,
                ];
              }
              if (
                !availableEntityTypes
                || availableEntityTypes.includes('Stix-Domain-Object')
              ) {
                result = [
                  ...R.pipe(
                    R.pathOr([], ['sdoTypes', 'edges']),
                    R.map((n) => ({
                      label: t(`entity_${n.node.label}`),
                      value: n.node.label,
                      type: n.node.label,
                    })),
                  )(data),
                  ...result,
                ];
              }
              toTypesTypes = R.sortWith([R.ascend(R.prop('label'))], result);
              if (this.props.allEntityTypes) {
                toTypesTypes = R.prepend(
                  { label: t('entity_All'), value: 'all', type: 'entity' },
                  toTypesTypes,
                );
              }
              this.setState({
                entities: {
                  ...this.state.entities,
                  toTypes: R.union(toTypesTypes, this.state.entities.toTypes),
                },
              });
            });
        }
        break;
      case 'relationship_type':
        // eslint-disable-next-line no-case-declarations
        let relationshipsTypes = [];
        if (availableRelationshipTypes) {
          relationshipsTypes = R.pipe(
            R.map((n) => ({
              label: t(`relationship_${n.toString()}`),
              value: n,
              type: n,
            })),
            R.sortWith([R.ascend(R.prop('label'))]),
          )(availableRelationshipTypes);
          if (this.props.allRelationshipTypes) {
            relationshipsTypes = R.prepend(
              {
                label: t('relationship_All'),
                value: 'all',
                type: 'relationship',
              },
              relationshipsTypes,
            );
          }
          this.setState({
            entities: {
              ...this.state.entities,
              relationship_type: R.union(
                relationshipsTypes,
                this.state.entities.relationship_type,
              ),
            },
          });
        } else {
          fetchQuery(filtersAllTypesQuery)
            .toPromise()
            .then((data) => {
              relationshipsTypes = R.pipe(
                R.pathOr([], ['sroTypes', 'edges']),
                R.map((n) => ({
                  label: t(`relationship_${n.node.label}`),
                  value: n.node.label,
                  type: n.node.label,
                })),
                R.sortWith([R.ascend(R.prop('label'))]),
              )(data);
              if (this.props.allRelationshipTypes) {
                relationshipsTypes = R.prepend(
                  {
                    label: t('relationship_All'),
                    value: 'all',
                    type: 'relationship',
                  },
                  relationshipsTypes,
                );
              }
              this.setState({
                entities: {
                  ...this.state.entities,
                  relationship_type: R.union(
                    relationshipsTypes,
                    this.state.entities.relationship_type,
                  ),
                },
              });
            });
        }
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

  handleChangeDate(filterKey, date) {
    this.setState({
      inputValues: R.assoc(filterKey, date, this.state.inputValues),
    });
  }

  handleAcceptDate(filterKey, date) {
    const { nsd } = this.props;
    if (date && date.toISOString()) {
      if (this.props.variant === 'dialog') {
        this.handleAddFilter(filterKey, date.toISOString(), nsd(date));
      } else {
        this.props.handleAddFilter(filterKey, date.toISOString(), nsd(date));
      }
    }
  }

  handleValidateDate(filterKey, event) {
    if (event.key === 'Enter') {
      if (this.state.inputValues[filterKey].toString() !== 'Invalid Date') {
        return this.handleAcceptDate(
          filterKey,
          this.state.inputValues[filterKey],
        );
      }
    }
    return null;
  }

  handleChangeKeyword(event) {
    this.setState({ keyword: event.target.value });
  }

  renderFilters() {
    const { t, classes, availableFilterKeys, variant, noDirectFilters } = this.props;
    const { entities, keyword, inputValues, searchScope } = this.state;
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
          if (
            filterKey.endsWith('start_date')
            || filterKey.endsWith('end_date')
          ) {
            return (
              <Grid key={filterKey} item={true} xs={6}>
                <DatePicker
                  label={t(`filter_${filterKey}`)}
                  value={inputValues[filterKey] || null}
                  variant="inline"
                  disableToolbar={false}
                  autoOk={true}
                  allowKeyboardControl={true}
                  onChange={this.handleChangeDate.bind(this, filterKey)}
                  onAccept={this.handleAcceptDate.bind(this, filterKey)}
                  renderInput={(params) => (
                    <TextField
                      variant="outlined"
                      size="small"
                      fullWidth={variant === 'dialog'}
                      onKeyDown={this.handleValidateDate.bind(this, filterKey)}
                      {...params}
                    />
                  )}
                />
              </Grid>
            );
          }
          let options = [];
          if (['fromId', 'toId'].includes(filterKey)) {
            if (searchScope[filterKey] && searchScope[filterKey].length > 0) {
              options = (entities[filterKey] || [])
                .filter((n) => (searchScope[filterKey] || []).includes(n.type))
                .sort((a, b) => (b.type ? -b.type.localeCompare(a.type) : 0));
            } else {
              // eslint-disable-next-line max-len
              options = (entities[filterKey] || []).sort((a, b) => (b.type ? -b.type.localeCompare(a.type) : 0));
            }
          } else if (entities[filterKey]) {
            options = entities[filterKey];
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
                options={options}
                onInputChange={this.searchEntities.bind(this, filterKey)}
                inputValue={inputValues[filterKey] || ''}
                onChange={this.handleChange.bind(this, filterKey)}
                groupBy={
                  ['fromId', 'toId'].includes(filterKey)
                    ? (option) => option.type
                    : null
                }
                isOptionEqualToValue={(option, value) => option.value === value.value
                }
                renderInput={(params) => (
                  <TextField
                    {...R.dissoc('InputProps', params)}
                    label={t(`filter_${filterKey}`)}
                    variant="outlined"
                    size="small"
                    fullWidth={true}
                    onFocus={this.searchEntities.bind(this, filterKey)}
                    InputProps={{
                      ...params.InputProps,
                      endAdornment: ['fromId', 'toId'].includes(filterKey)
                        ? this.renderSearchScopeSelection(filterKey)
                        : params.InputProps.endAdornment,
                    }}
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
    const { t, classes, availableFilterKeys, noDirectFilters, size, fontSize } = this.props;
    const { open, anchorEl, entities, inputValues, searchScope } = this.state;
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
            size={size || 'large'}
          >
            <FilterListOutlined fontSize={fontSize || 'medium'} />
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
          elevation={1}
        >
          {this.renderFilters()}
        </Popover>
        {!noDirectFilters
          && R.filter(
            (n) => R.includes(n, directFilters),
            availableFilterKeys,
          ).map((filterKey) => {
            let options = [];
            if (['fromId', 'toId'].includes(filterKey)) {
              if (searchScope[filterKey] && searchScope[filterKey].length > 0) {
                options = (entities[filterKey] || [])
                  .filter((n) => (searchScope[filterKey] || []).includes(n.type))
                  .sort((a, b) => (b.type ? -b.type.localeCompare(a.type) : 0));
              } else {
                // eslint-disable-next-line max-len
                options = (entities[filterKey] || []).sort((a, b) => (b.type ? -b.type.localeCompare(a.type) : 0));
              }
            } else if (entities[filterKey]) {
              options = entities[filterKey];
            }
            return (
              <Autocomplete
                key={filterKey}
                className={classes.autocomplete}
                selectOnFocus={true}
                autoSelect={false}
                autoHighlight={true}
                options={options}
                getOptionLabel={(option) => (option.label ? option.label : '')}
                noOptionsText={t('No available options')}
                onInputChange={this.searchEntities.bind(this, filterKey)}
                onChange={this.handleChange.bind(this, filterKey)}
                isOptionEqualToValue={(option, value) => option.value === value}
                inputValue={inputValues[filterKey] || ''}
                groupBy={
                  ['fromId', 'toId'].includes(filterKey)
                    ? (option) => option.type
                    : null
                }
                renderInput={(params) => (
                  <TextField
                    {...R.dissoc('InputProps', params)}
                    label={t(`filter_${filterKey}`)}
                    variant="outlined"
                    size="small"
                    fullWidth={true}
                    onFocus={this.searchEntities.bind(this, filterKey)}
                    InputProps={{
                      ...params.InputProps,
                      endAdornment: ['fromId', 'toId'].includes(filterKey)
                        ? this.renderSearchScopeSelection(filterKey)
                        : params.InputProps.endAdornment,
                    }}
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
            );
          })}
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

  handleOpenSearchScope(key, event) {
    const { openSearchScope, anchorElSearchScope } = this.state;
    this.setState({
      openSearchScope: R.assoc(key, true, openSearchScope),
      anchorElSearchScope: R.assoc(
        key,
        event.currentTarget,
        anchorElSearchScope,
      ),
    });
  }

  handleCloseSearchScope(key) {
    const { openSearchScope, anchorElSearchScope } = this.state;
    this.setState({
      openSearchScope: R.assoc(key, false, openSearchScope),
      anchorElSearchScope: R.assoc(key, null, anchorElSearchScope),
    });
  }

  handleToggleSearchScope(key, value) {
    const { searchScope } = this.state;
    this.setState({
      searchScope: R.assoc(
        key,
        (searchScope[key] || []).includes(value)
          ? searchScope[key].filter((n) => n !== value)
          : [...(searchScope[key] || []), value],
        searchScope,
      ),
    });
  }

  renderSearchScopeSelection(key) {
    const { t, classes } = this.props;
    const { openSearchScope, searchScope, anchorElSearchScope } = this.state;
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
    )(entityTypes);
    return (
      <React.Fragment>
        <InputAdornment position="start">
          <IconButton
            onClick={this.handleOpenSearchScope.bind(this, key)}
            size="small"
            edge="end"
            style={{ marginRight: -8 }}
          >
            <PaletteOutlined
              fontSize="small"
              color={
                searchScope[key] && searchScope[key].length > 0
                  ? 'secondary'
                  : 'primary'
              }
            />
          </IconButton>
          <Popover
            classes={{ paper: classes.container2 }}
            open={openSearchScope[key]}
            anchorEl={anchorElSearchScope[key]}
            onClose={this.handleCloseSearchScope.bind(this, key)}
            anchorOrigin={{
              vertical: 'center',
              horizontal: 'right',
            }}
            transformOrigin={{
              vertical: 'center',
              horizontal: 'left',
            }}
            elevation={8}
          >
            <MenuList dense={true}>
              {entitiesTypes.map((entityType) => (
                <MenuItem
                  key={entityType.value}
                  value={entityType.value}
                  dense={true}
                  onClick={this.handleToggleSearchScope.bind(
                    this,
                    key,
                    entityType.value,
                  )}
                >
                  <Checkbox
                    size="small"
                    checked={(searchScope[key] || []).includes(
                      entityType.value,
                    )}
                  />
                  <ListItemText primary={entityType.label} />
                </MenuItem>
              ))}
            </MenuList>
          </Popover>
        </InputAdornment>
      </React.Fragment>
    );
  }

  renderDialogFilters() {
    const { t, classes, disabled, size, fontSize } = this.props;
    const { open, filters } = this.state;
    return (
      <React.Fragment>
        <Tooltip title={t('Advanced search')}>
          <IconButton
            onClick={this.handleOpenFilters.bind(this)}
            disabled={disabled}
            size={size || 'medium'}
          >
            <ToyBrickSearchOutline fontSize={fontSize || 'medium'} />
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
            <Button onClick={this.handleCloseFilters.bind(this)}>
              {t('Cancel')}
            </Button>
            <Button color="secondary" onClick={this.handleSearch.bind(this)}>
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
  nsd: PropTypes.func,
  availableFilterKeys: PropTypes.array,
  handleAddFilter: PropTypes.func,
  variant: PropTypes.string,
  disabled: PropTypes.bool,
  noDirectFilters: PropTypes.bool,
  allEntityTypes: PropTypes.bool,
  availableEntityTypes: PropTypes.array,
  availableRelationshipTypes: PropTypes.array,
};

export default R.compose(
  inject18n,
  withRouter,
  withTheme,
  withStyles(styles),
)(Filters);
