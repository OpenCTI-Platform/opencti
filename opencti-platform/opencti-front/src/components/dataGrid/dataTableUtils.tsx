import React, { ReactNode } from 'react';
import Chip from '@mui/material/Chip';
import makeStyles from '@mui/styles/makeStyles';
import StixCoreObjectLabels from '@components/common/stix_core_objects/StixCoreObjectLabels';
import Tooltip from '@mui/material/Tooltip';
import { Link } from 'react-router-dom';
import { useTheme } from '@mui/styles';
import type { DataTableColumn } from './dataTableTypes';
import { DataTableProps, DataTableVariant } from './dataTableTypes';
import ItemMarkings from '../ItemMarkings';
import ItemStatus from '../ItemStatus';
import { emptyFilled, truncate } from '../../utils/String';
import ItemPriority from '../ItemPriority';
import { isNotEmptyField } from '../../utils/utils';
import RatingField from '../fields/RatingField';
import ItemConfidence from '../ItemConfidence';
import ItemPatternType from '../ItemPatternType';
import type { Theme } from '../Theme';
import { getMainRepresentative } from '../../utils/defaultRepresentatives';
import ItemEntityType from '../ItemEntityType';
import ItemOpenVocab from '../ItemOpenVocab';
import ItemBoolean from '../ItemBoolean';
import ItemSeverity from '../ItemSeverity';
import { APP_BASE_PATH } from '../../relay/environment';

const MAGICAL_SIZE = 0.113;

const chipStyle = {
  fontSize: '12px',
  lineHeight: '12px',
  height: '20px',
  marginRight: '7px',
  borderRadius: '10px',
};

/* eslint-disable @typescript-eslint/no-explicit-any */
type TextInTooltip = (val?: string, helpers?: any) => ReactNode;
export const textInTooltip: TextInTooltip = (val, helpers) => {
  const value = val ?? '-';
  const { column: { size } } = helpers;
  return (
    <Tooltip title={value}>
      <div>{truncate(value, size * MAGICAL_SIZE, false)}</div>
    </Tooltip>
  );
};

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles<Theme>((theme) => ({
  chipInList: {
    fontSize: 12,
    height: 20,
    float: 'left',
    width: 120,
    textTransform: 'uppercase',
    borderRadius: 4,
  },
  chip: {
    fontSize: 13,
    lineHeight: '12px',
    height: 20,
    textTransform: 'uppercase',
    borderRadius: 4,
    cursor: 'pointer',
    '&:hover': {
      backgroundColor: theme.palette.primary.main,
    },
  },
  chipNoLink: {
    fontSize: 13,
    lineHeight: '12px',
    height: 20,
    textTransform: 'uppercase',
    borderRadius: 4,
  },
  positive: {
    fontSize: 12,
    lineHeight: '12px',
    height: 20,
    backgroundColor: 'rgba(244, 67, 54, 0.08)',
    color: '#f44336',
    textTransform: 'uppercase',
    borderRadius: '0',
  },
  negative: {
    fontSize: 12,
    lineHeight: '12px',
    height: 20,
    backgroundColor: 'rgba(76, 175, 80, 0.08)',
    color: '#4caf50',
    textTransform: 'uppercase',
    borderRadius: '0',
  },
}));

const defaultRender: DataTableColumn['render'] = (data, { column: { size } }) => (<Tooltip title={data}>
  <div>{truncate(data, size * MAGICAL_SIZE)}</div>
</Tooltip>);

const defaultColumns: DataTableProps['dataColumns'] = {
  allowed_markings: {
    id: 'allowed_markings',
    percentWidth: 16,
    label: 'Allowed markings',
    isSortable: false,
    render: ({ allowed_markings }) => (
      <ItemMarkings
        variant="inList"
        markingDefinitions={allowed_markings ?? []}
        limit={2}
      />),
  },
  analyses: {
    id: 'analyses',
    label: 'Analyses',
    percentWidth: 8,
    isSortable: false,
    render: ({ id, entity_type, containersNumber }, { n }) => {
      const classes = useStyles();
      const link = `/dashboard/observations/${
        entity_type === 'Artifact' ? 'artifacts' : 'observables'
      }/${id}`;
      const linkAnalyses = `${link}/analyses`;
      return (
        <>
          {[
            'Note',
            'Opinion',
            'Course-Of-Action',
            'Data-Component',
            'Data-Source',
          ].includes(entity_type) ? (
            <Chip
              classes={{ root: classes.chipNoLink }}
              label={n(containersNumber.total)}
            />
            ) : (
              <Chip
                classes={{ root: classes.chip }}
                label={n(containersNumber.total)}
                component={Link}
                to={linkAnalyses}
              />
            )}
        </>
      );
    },
  },
  attribute_abstract: {
    id: 'attribute_abstract',
    label: 'Abstract',
    percentWidth: 25,
    isSortable: true,
    render: ({ attribute_abstract, content }, helpers) => {
      return defaultRender(attribute_abstract || content, helpers);
    },
  },
  attribute_count: {
    id: 'attribute_count',
    label: 'Nb.',
    percentWidth: 4,
    isSortable: true,
    render: ({ attribute_count }, helpers) => defaultRender(String(attribute_count), helpers),
  },
  channel_types: {
    id: 'channel_types',
    label: 'Types',
    percentWidth: 20,
    isSortable: true,
    render: ({ channel_types }, helpers) => {
      const value = channel_types ? channel_types.join(', ') : '-';
      return defaultRender(value, helpers);
    },
  },
  color: {
    id: 'color',
    label: 'Color',
    percentWidth: 25,
    isSortable: true,
    render: ({ color }, { column: { size } }) => (
      <Tooltip title={color}>
        <>
          <div
            style={{
              backgroundColor: color,
              height: 20,
              width: 20,
              display: 'inline-flex',
              borderRadius: 20,
              marginRight: 5,
            }}
          />
          {truncate(color, size * MAGICAL_SIZE)}
        </>
      </Tooltip>
    ),
  },
  confidence: {
    id: 'confidence',
    label: 'Confidence',
    percentWidth: 10,
    isSortable: true,
    render: ({ confidence, entity_type }) => (
      <ItemConfidence confidence={confidence} entityType={entity_type} variant="inList" />
    ),
  },
  context: {
    id: 'context',
    label: 'Context',
    percentWidth: 10,
    isSortable: true,
    render: ({ context }) => {
      const classes = useStyles();
      return (
        <Chip
          classes={{ root: classes.chipInList }}
          color="primary"
          variant="outlined"
          label={context}
        />
      );
    },
  },
  created: {
    id: 'created',
    label: 'Original creation date',
    percentWidth: 15,
    isSortable: true,
    render: ({ created }, helpers) => defaultRender(helpers.fd(created), helpers),
  },
  created_at: {
    id: 'created_at',
    label: 'Platform creation date',
    percentWidth: 15,
    isSortable: true,
    render: ({ created_at }, helpers) => defaultRender(helpers.fd(created_at), helpers),
  },
  createdBy: {
    id: 'createdBy',
    label: 'Author',
    percentWidth: 12,
    render: ({ createdBy }) => createdBy?.name ?? '-',
  },
  creator: {
    id: 'creator',
    label: 'Creators',
    percentWidth: 12,
    render: ({ creators }, helpers) => {
      const value = isNotEmptyField(creators) ? creators.map((c: { name: string }) => c.name).join(', ') : '-';
      return defaultRender(value, helpers);
    },
  },
  entity_type: {
    id: 'entity_type',
    label: 'Type',
    percentWidth: 10,
    isSortable: false,
    render: (data) => <ItemEntityType showIcon entityType={data.entity_type} inList />,
  },
  event_types: {
    id: 'event_types',
    label: 'Types',
    percentWidth: 20,
    isSortable: true,
    render: ({ event_types }, helpers) => {
      const value = event_types ? event_types.join(', ') : '-';
      return defaultRender(value, helpers);
    },
  },
  external_id: {
    id: 'external_id',
    label: 'External ID',
    percentWidth: 10,
    isSortable: true,
    render: ({ external_id }, helpers) => defaultRender(external_id, helpers),
  },
  first_observed: {
    id: 'first_observed',
    label: 'First obs.',
    percentWidth: 14,
    isSortable: true,
    render: ({ first_observed }, { nsdt }) => nsdt(first_observed),
  },
  first_seen: {
    id: 'first_seen',
    label: 'First obs.',
    percentWidth: 12,
    isSortable: true,
    render: ({ first_seen }, { nsdt }) => nsdt(first_seen),
  },
  fromName: {
    id: 'fromName',
    label: 'From name',
    percentWidth: 18,
    isSortable: false,
    render: ({ from }, helpers) => {
      const value = from ? getMainRepresentative(from) : helpers.t_i18n('Restricted');
      return defaultRender(value, helpers);
    },
  },
  incident_type: {
    id: 'incident_type',
    label: 'Incident type',
    percentWidth: 9,
    isSortable: true,
    render: ({ incident_type }, { t_i18n, storageHelpers: { handleAddFilter } }) => {
      const classes = useStyles();
      return (
        <Chip
          classes={{ root: classes.chipInList }}
          color="primary"
          variant="outlined"
          label={incident_type || t_i18n('Unknown')}
          onClick={(e) => {
            e.preventDefault();
            e.stopPropagation();
            handleAddFilter('incident_type', incident_type ?? null, 'eq');
          }}
        />
      );
    },
  },
  infrastructure_types: {
    id: 'infrastructure_types',
    label: 'Type',
    percentWidth: 8,
    isSortable: true,
    render: ({ infrastructure_types }, { t_i18n, storageHelpers: { handleAddFilter } }) => {
      const classes = useStyles();
      return (
        <Chip
          classes={{ root: classes.chipInList }}
          color="primary"
          variant="outlined"
          label={infrastructure_types?.at(0) ?? t_i18n('Unknown')}
          onClick={(e) => {
            e.preventDefault();
            e.stopPropagation();
            handleAddFilter('infrastructure_types', infrastructure_types?.at(0) ?? null, 'eq');
          }}
        />
      );
    },
  },
  is_family: {
    id: 'is_family',
    label: 'Is family',
    percentWidth: 8,
    isSortable: true,
    render: ({ is_family }, { t_i18n }) => (
      <ItemBoolean
        status={is_family}
        label={is_family ? t_i18n('Yes') : t_i18n('No')}
      />
    ),
  },
  isShared: {
    id: 'isShared',
    label: 'Shared',
    percentWidth: 8,
    isSortable: false,
    render: ({ isShared }, { t_i18n }) => (
      <ItemBoolean
        status={isShared}
        label={isShared ? t_i18n('Yes') : t_i18n('No')}
      />
    ),
  },
  killChainPhase: {
    id: 'killChainPhase',
    label: 'Kill chain phase',
    percentWidth: 15,
    isSortable: false,
    render: ({ killChainPhases }) => ((killChainPhases && killChainPhases.length > 0)
      ? `[${killChainPhases[0].kill_chain_name}] ${killChainPhases[0].phase_name}`
      : '-'),
  },
  kill_chain_name: {
    id: 'kill_chain_name',
    label: 'Kill chain name',
    percentWidth: 40,
    isSortable: true,
    render: ({ kill_chain_name }, helpers) => defaultRender(kill_chain_name, helpers),
  },
  last_observed: {
    id: 'last_observed',
    label: 'Last obs.',
    percentWidth: 14,
    isSortable: true,
    render: ({ last_observed }, { nsdt }) => nsdt(last_observed),
  },
  last_seen: {
    id: 'last_seen',
    label: 'Last obs.',
    percentWidth: 12,
    isSortable: true,
    render: ({ last_seen }, { nsdt }) => nsdt(last_seen),
  },
  malware_types: {
    id: 'malware_types',
    label: 'Malware types',
    percentWidth: 15,
    isSortable: true,
    render: ({ malware_types }, helpers) => {
      const value = malware_types ? malware_types.join(', ') : '-';
      return defaultRender(value, helpers);
    },
  },
  modified: {
    id: 'modified',
    label: 'Modification date',
    percentWidth: 15,
    isSortable: true,
    render: ({ modified }, { fd }) => fd(modified),
  },
  name: {
    id: 'name',
    label: 'Name',
    percentWidth: 25,
    isSortable: true,
    render: (data, helpers) => defaultRender(getMainRepresentative(data), helpers),
  },
  note_types: {
    id: 'note_types',
    label: 'Type',
    percentWidth: 10,
    isSortable: true,
    render: ({ note_types }, { t_i18n, storageHelpers: { handleAddFilter } }) => {
      const classes = useStyles();
      return (
        <Chip
          classes={{ root: classes.chipInList }}
          color="primary"
          variant="outlined"
          label={note_types?.at(0) ?? t_i18n('Unknown')}
          onClick={(e) => {
            e.preventDefault();
            e.stopPropagation();
            handleAddFilter('note_types', note_types?.at(0) ?? null, 'eq');
          }}
        />
      );
    },
  },
  number_observed: {
    id: 'number_observed',
    label: 'Nb.',
    percentWidth: 8,
    isSortable: true,
    render: ({ number_observed }, { n }) => (<Tooltip title={number_observed}><>{n(number_observed)}</>
    </Tooltip>),
  },
  objectAssignee: {
    id: 'objectAssignee',
    label: 'Assignees',
    percentWidth: 10,
    isSortable: false,
    render: ({ objectAssignee }, helpers) => {
      const value = isNotEmptyField(objectAssignee) ? objectAssignee.map((c: { name: string }) => c.name).join(', ') : '-';
      return defaultRender(value, helpers);
    },
  },
  objectLabel: {
    id: 'objectLabel',
    label: 'Labels',
    percentWidth: 15,
    isSortable: false,
    render: ({ objectLabel }, { storageHelpers: { handleAddFilter } }) => {
      return (
        <StixCoreObjectLabels
          variant="inList"
          labels={objectLabel}
          onClick={handleAddFilter}
        />
      );
    },
  },
  objectMarking: {
    id: 'objectMarking',
    label: 'Marking',
    percentWidth: 8,
    isSortable: true,
    render: ({ objectMarking }, { storageHelpers: { handleAddFilter } }) => (
      <ItemMarkings
        variant="inList"
        markingDefinitions={objectMarking ?? []}
        limit={1}
        onClick={handleAddFilter}
      />
    ),
  },
  observable_value: {
    id: 'observable_value',
    label: 'Value',
    percentWidth: 20,
    isSortable: false,
    // Please check the String.jsx->renderObservableValue. It should have the same behavior and will replace it at the end.
    render: (observable, helpers) => {
      const theme = useTheme<Theme>();
      switch (observable.entity_type) {
        case 'IPv4-Addr':
        case 'IPv6-Addr': {
          const country = observable.countries?.edges?.[0]?.node;
          if (country) {
            const flag = (country.x_opencti_aliases ?? []).filter((n: string) => n.length === 2)[0];
            if (flag) {
              return (
                <div style={{ display: 'flex', gap: theme.spacing(1), alignItems: 'center' }}>
                  <Tooltip title={country.name}>
                    <img
                      style={{ width: 20 }}
                      src={`${APP_BASE_PATH}/static/flags/4x3/${flag.toLowerCase()}.svg`}
                      alt={country.name}
                    />
                  </Tooltip>
                  <div>
                    {defaultRender(observable.observable_value, helpers)}
                  </div>
                </div>
              );
            }
          }
          return defaultRender(observable.observable_value, helpers);
        }
        default:
          return defaultRender(observable.observable_value, helpers);
      }
    },
  },
  operatingSystem: {
    id: 'operatingSystem',
    label: 'Operating System',
    percentWidth: 15,
    isSortable: false,
    render: ({ operatingSystem }) => (
      <Tooltip
        title={operatingSystem?.name}
      >
        <>{operatingSystem?.name ?? '-'}</>
      </Tooltip>),
  },
  owner: {
    id: 'owner',
    label: 'Owner',
    percentWidth: 12,
    isSortable: true,
    render: ({ owner }, h) => textInTooltip(owner.name, h),
  },
  pattern_type: {
    id: 'pattern_type',
    label: 'Pattern type',
    percentWidth: 10,
    isSortable: true,
    render: ({ pattern_type }) => (<ItemPatternType variant="inList" label={pattern_type} />),
  },
  phase_name: {
    id: 'phase_name',
    label: 'Phase name',
    percentWidth: 35,
    isSortable: true,
    render: ({ phase_name }, helpers) => defaultRender(phase_name, helpers),
  },
  primary_motivation: {
    id: 'primary_motivation',
    label: 'Primary motivation',
    percentWidth: 10,
    isSortable: true,
    render: ({ primary_motivation }) => (
      <ItemOpenVocab
        type="attack-motivation-ov"
        value={primary_motivation}
      />
    ),
  },
  priority: {
    id: 'priority',
    label: 'Priority',
    percentWidth: 10,
    isSortable: true,
    render: ({ priority }, { t_i18n }) => (
      <ItemPriority
        variant="inList"
        priority={priority}
        label={priority || t_i18n('Unknown')}
      />
    ),
  },
  product: {
    id: 'product',
    label: 'Product',
    percentWidth: 15,
    isSortable: true,
    render: ({ product }, helpers) => defaultRender(product, helpers),
  },
  published: {
    id: 'published',
    label: 'Date',
    percentWidth: 10,
    isSortable: true,
    render: ({ published }, { fd }) => fd(published),
  },
  rating: {
    id: 'rating',
    label: 'Rating',
    percentWidth: 10,
    isSortable: true,
    render: ({ rating }) => (
      <RatingField
        rating={rating}
        size="tiny"
        readOnly
        style={{ paddingTop: 2 }}
      />
    ),
  },
  relationship_type: {
    id: 'relationship_type',
    label: 'Type',
    percentWidth: 7,
    isSortable: true,
    render: ({ relationship_type }, { t_i18n, storageHelpers: { handleAddFilter } }) => {
      const classes = useStyles();
      return (
        <Chip
          classes={{ root: classes.chipInList }}
          color="primary"
          variant="outlined"
          label={relationship_type ?? t_i18n('Unknown')}
          onClick={(e) => {
            e.preventDefault();
            e.stopPropagation();
            handleAddFilter('relationship_type', relationship_type ?? null, 'eq');
          }}
        />
      );
    },
  },
  report_types: {
    id: 'report_types',
    label: 'Type',
    percentWidth: 10,
    isSortable: true,
    render: ({ report_types }, { t_i18n, storageHelpers: { handleAddFilter } }) => {
      const classes = useStyles();
      return (
        <Chip
          classes={{ root: classes.chipInList }}
          color="primary"
          variant="outlined"
          label={report_types?.at(0) ?? t_i18n('Unknown')}
          onClick={(e) => {
            e.preventDefault();
            e.stopPropagation();
            handleAddFilter('report_types', report_types?.at(0) ?? null, 'eq');
          }}
        />
      );
    },
  },
  resource_level: {
    id: 'resource_level',
    label: 'Resource level',
    percentWidth: 10,
    isSortable: true,
    render: (threatActorGroup) => (
      <ItemOpenVocab
        type="attack-resource-level-ov"
        value={threatActorGroup.resource_level}
      />
    ),
  },
  result_name: {
    id: 'result_name',
    label: 'Result name',
    percentWidth: 15,
    isSortable: true,
    render: ({ result_name }, helpers) => defaultRender(result_name, helpers),
  },
  secondary_motivations: {
    id: 'secondary_motivations',
    label: 'Secondary motivations',
    percentWidth: 10,
    isSortable: false,
    render: ({ secondary_motivations }, helpers) => {
      const value = secondary_motivations ? secondary_motivations.join(', ') : '-';
      return defaultRender(value, helpers);
    },
  },
  severity: {
    id: 'severity',
    label: 'Severity',
    percentWidth: 10,
    isSortable: true,
    render: ({ severity }, { t_i18n }) => (
      <ItemSeverity
        variant="inList"
        severity={severity}
        label={severity || t_i18n('Unknown')}
      />
    ),
  },
  sophistication: {
    id: 'sophistication',
    label: 'Sophistication',
    percentWidth: 10,
    isSortable: true,
    render: (threatActorGroup) => (
      <ItemOpenVocab
        type="threat-actor-group-sophistication-ov"
        value={threatActorGroup.sophistication}
      />
    ),
  },
  source_name: {
    id: 'source_name',
    label: 'Source name',
    percentWidth: 15,
    isSortable: true,
    render: ({ source_name }, helpers) => defaultRender(source_name, helpers),
  },
  start_time: {
    id: 'start_time',
    label: 'Start date',
    percentWidth: 15,
    isSortable: true,
    render: ({ start_time }, { fd }) => fd(start_time),
  },
  stop_time: {
    id: 'stop_time',
    label: 'End date',
    percentWidth: 15,
    isSortable: true,
    render: ({ stop_time }, { fd }) => fd(stop_time),
  },
  submitted: {
    id: 'submitted',
    label: 'Submission date',
    percentWidth: 12,
    isSortable: true,
    render: ({ submitted }, { fd }) => fd(submitted),
  },
  tags: {
    id: 'tags',
    label: 'Tags',
    percentWidth: 15,
    isSortable: false,
    render: ({ tags }) => {
      if (!tags || tags.length === 0) return '-';
      return (
        <Tooltip
          title={(
            <div style={{ display: 'flex', flexWrap: 'wrap', rowGap: '4px' }}>
              {tags.map((tag: string) => (
                <Chip key={tag} label={tag} style={chipStyle} />
              ))}
            </div>
          )}
        >
          <div>
            <Chip label={tags[0]} style={chipStyle} />
            <Chip label="..." style={chipStyle} />
          </div>
        </Tooltip>
      );
    },
  },
  threat_actor_types: {
    id: 'threat_actor_types',
    label: 'Types',
    percentWidth: 20,
    isSortable: true,
    render: ({ threat_actor_types }, helpers) => {
      const value = threat_actor_types ? threat_actor_types.join(', ') : '-';
      return defaultRender(value, helpers);
    },
  },
  toName: {
    id: 'toName',
    label: 'To name',
    percentWidth: 18,
    isSortable: false,
    render: ({ to }, helpers) => {
      const value = to ? getMainRepresentative(to) : helpers.t_i18n('Restricted');
      return defaultRender(value, helpers);
    },
  },
  updated_at: {
    id: 'updated_at',
    label: 'Modification date',
    percentWidth: 15,
    isSortable: true,
    render: ({ updated_at }, { fd }) => fd(updated_at),
  },
  url: {
    id: 'url',
    label: 'URL',
    percentWidth: 45,
    isSortable: true,
    render: ({ url }, helpers) => defaultRender(url, helpers),
  },
  user_email: {
    id: 'user_email',
    label: 'Email',
    percentWidth: 50,
    isSortable: false,
    render: ({ user_email }, helpers) => defaultRender(user_email, helpers),
  },
  value: {
    id: 'value',
    label: 'Value',
    percentWidth: 22,
    isSortable: false,
    render: (node, helpers) => {
      const value = getMainRepresentative(node);
      return defaultRender(value, helpers);
    },
  },
  x_mitre_id: {
    id: 'x_mitre_id',
    label: 'ID',
    percentWidth: 10,
    isSortable: true,
    render: ({ x_mitre_id }) => <code>{emptyFilled(x_mitre_id)}</code>,
  },
  x_opencti_order: {
    id: 'x_opencti_order',
    label: 'Order',
    percentWidth: 10,
    isSortable: true,
    render: ({ x_opencti_order }, helpers) => defaultRender(x_opencti_order.toString(), helpers),
  },
  x_opencti_negative: {
    id: 'x_opencti_negative',
    label: 'Qualification',
    percentWidth: 15,
    isSortable: true,
    render: ({ x_opencti_negative }, { t_i18n }) => {
      const classes = useStyles();
      return (
        <Chip
          classes={{
            root: x_opencti_negative
              ? classes.negative
              : classes.positive,
          }}
          label={
            x_opencti_negative
              ? t_i18n('False positive')
              : t_i18n('True positive')
          }
        />
      );
    },
  },
  x_opencti_cvss_base_severity: {
    id: 'x_opencti_cvss_base_severity',
    label: 'CVSS3 - Severity',
    percentWidth: 15,
    isSortable: true,
    render: ({ x_opencti_cvss_base_severity }, { t_i18n }) => (
      <ItemSeverity
        severity={x_opencti_cvss_base_severity}
        label={x_opencti_cvss_base_severity || t_i18n('Unknown')}
      />
    ),
  },
  x_opencti_organization_type: {
    id: 'x_opencti_organization_type',
    label: 'Type',
    percentWidth: 15,
    isSortable: true,
    render: ({ x_opencti_organization_type }, { storageHelpers: { handleAddFilter } }) => {
      const classes = useStyles();
      return (
        <Chip
          classes={{ root: classes.chipInList }}
          color="primary"
          variant="outlined"
          label={x_opencti_organization_type ?? 'Unknown'}
          onClick={(e) => {
            e.preventDefault();
            e.stopPropagation();
            handleAddFilter('x_opencti_organization_type', x_opencti_organization_type ?? null, 'eq');
          }}
        />
      );
    },
  },
  x_opencti_workflow_id: {
    id: 'x_opencti_workflow_id',
    label: 'Status',
    percentWidth: 8,
    isSortable: true,
    render: ({ status, workflowEnabled }, { variant, storageHelpers: { handleAddFilter } }) => (
      <ItemStatus
        status={status}
        variant={variant === DataTableVariant.default ? 'inList' : 'inLine'}
        disabled={!workflowEnabled}
        onClick={handleAddFilter}
      />
    ),
  },
  file_name: {
    id: 'file_name',
    label: 'File name',
    percentWidth: 12,
    isSortable: false,
    render: (data, { column: { size } }) => {
      const file = (data.importFiles?.edges && data.importFiles.edges.length > 0)
        ? data.importFiles.edges[0]?.node
        : { name: 'N/A', metaData: { mimetype: 'N/A' }, size: 0 };
      return (<Tooltip title={file?.name}><>{truncate(file?.name, size * MAGICAL_SIZE)}</>
      </Tooltip>);
    },
  },
  file_mime_type: {
    id: 'file_mime_type',
    label: 'Mime/Type',
    percentWidth: 8,
    isSortable: false,
    render: (data, { column: { size } }) => {
      const file = (data.importFiles?.edges && data.importFiles.edges.length > 0)
        ? data.importFiles.edges[0]?.node
        : { name: 'N/A', metaData: { mimetype: 'N/A' }, size: 0 };
      return (<Tooltip title={file?.metaData?.mimetype}><>{truncate(file?.metaData?.mimetype, size * MAGICAL_SIZE)}</>
      </Tooltip>);
    },
  },
  file_size: {
    id: 'file_size',
    label: 'File size',
    percentWidth: 8,
    isSortable: false,
    render: (data, { b }) => {
      const file = (data.importFiles?.edges && data.importFiles.edges.length > 0)
        ? data.importFiles.edges[0]?.node
        : { name: 'N/A', metaData: { mimetype: 'N/A' }, size: 0 };
      return (<Tooltip title={file?.metaData?.mimetype}><>{b(file?.size)}</>
      </Tooltip>);
    },
  },
  valid_until: {
    id: 'valid_until',
    label: 'Valid until',
    percentWidth: 10,
    isSortable: true,
    render: ({ valid_until }, { nsdt }) => <Tooltip title={nsdt(valid_until)}>{nsdt(valid_until)}</Tooltip>,
  },
};

export const defaultColumnsMap = new Map<string, Partial<DataTableColumn>>(Object.entries(defaultColumns));
