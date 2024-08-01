import React, { ReactNode } from 'react';
import Chip from '@mui/material/Chip';
import makeStyles from '@mui/styles/makeStyles';
import StixCoreObjectLabels from '@components/common/stix_core_objects/StixCoreObjectLabels';
import Tooltip from '@mui/material/Tooltip';
import { Link } from 'react-router-dom';
import type { DataTableColumn, DataTableContextProps } from './dataTableTypes';
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
      <div>{truncate(value, size * MAGICAL_SIZE)}</div>
    </Tooltip>
  );
};

// TODO improve this with a proper context definition
export const DataTableContext = React.createContext({});
export const useDataTableContext = (): DataTableContextProps => React.useContext(DataTableContext) as DataTableContextProps;

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles<Theme>((theme) => ({
  chipInList: {
    fontSize: 12,
    height: 20,
    float: 'left',
    width: 120,
    textTransform: 'uppercase',
    borderRadius: '0',
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

const defaultColumns: DataTableProps['dataColumns'] = {
  allowed_markings: {
    id: 'allowed_markings',
    flexSize: 16,
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
    flexSize: 8,
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
    flexSize: 25,
    isSortable: true,
    render: ({ attribute_abstract, content }, { column: { size } }) => {
      const data = attribute_abstract || content;
      return (<Tooltip title={data}><div>{truncate(data, size * MAGICAL_SIZE)}</div></Tooltip>);
    },
  },
  attribute_count: {
    id: 'attribute_count',
    label: 'Nb.',
    flexSize: 4,
    isSortable: true,
    render: ({ attribute_count }) => (<Tooltip title={attribute_count}><>{attribute_count}</></Tooltip>),
  },
  channel_types: {
    id: 'channel_types',
    label: 'Types',
    flexSize: 20,
    isSortable: true,
    render: ({ channel_types }, { column: { size } }) => {
      const value = channel_types ? channel_types.join(', ') : '-';
      return (<Tooltip title={value}><div>{truncate(value, size * MAGICAL_SIZE)}</div></Tooltip>);
    },
  },
  color: {
    id: 'color',
    label: 'Color',
    flexSize: 25,
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
    flexSize: 10,
    isSortable: true,
    render: ({ confidence, entity_type }) => (
      <ItemConfidence confidence={confidence} entityType={entity_type} variant="inList" />
    ),
  },
  context: {
    id: 'context',
    label: 'Context',
    flexSize: 10,
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
    label: 'Original creation',
    flexSize: 15,
    isSortable: true,
    render: ({ created }, { fd }) => fd(created),
  },
  created_at: {
    id: 'created_at',
    label: 'Platform creation date',
    flexSize: 15,
    isSortable: true,
    render: ({ created_at }, { fd }) => fd(created_at),
  },
  createdBy: {
    id: 'createdBy',
    label: 'Author',
    flexSize: 12,
    render: ({ createdBy }) => createdBy?.name ?? '-',
  },
  creator: {
    id: 'creator',
    label: 'Creators',
    flexSize: 12,
    render: ({ creators }, { column: { size } }) => {
      const value = isNotEmptyField(creators) ? creators.map((c: { name: string }) => c.name).join(', ') : '-';
      return (<Tooltip title={value}><div>{truncate(value, size * MAGICAL_SIZE)}</div></Tooltip>);
    },
  },
  entity_type: {
    id: 'entity_type',
    label: 'Type',
    flexSize: 10,
    isSortable: false,
    render: (data) => <ItemEntityType entityType={data.entity_type} />,
  },
  event_types: {
    id: 'event_types',
    label: 'Types',
    flexSize: 20,
    isSortable: true,
    render: ({ event_types }, { column: { size } }) => {
      const value = event_types ? event_types.join(', ') : '-';
      return (<Tooltip title={value}><div>{truncate(value, size * MAGICAL_SIZE)}</div></Tooltip>);
    },
  },
  external_id: {
    id: 'external_id',
    label: 'External ID',
    flexSize: 10,
    isSortable: true,
    render: ({ external_id }, { column: { size } }) => (
      <Tooltip title={external_id}><div>{truncate(external_id, size * MAGICAL_SIZE)}</div></Tooltip>
    ),
  },
  first_observed: {
    id: 'first_observed',
    label: 'First obs.',
    flexSize: 14,
    isSortable: true,
    render: ({ first_observed }, { nsdt }) => nsdt(first_observed),
  },
  first_seen: {
    id: 'first_seen',
    label: 'First obs.',
    flexSize: 12,
    isSortable: true,
    render: ({ first_seen }, { nsdt }) => nsdt(first_seen),
  },
  fromName: {
    id: 'fromName',
    label: 'From name',
    flexSize: 18,
    isSortable: false,
    render: ({ from }, { column: { size }, t_i18n }) => {
      const value = from ? getMainRepresentative(from) : t_i18n('Restricted');
      return (<Tooltip title={value}><div>{truncate(value, size * MAGICAL_SIZE)}</div></Tooltip>);
    },
  },
  incident_type: {
    id: 'incident_type',
    label: 'Incident type',
    flexSize: 9,
    isSortable: true,
    render: ({ incident_type }, { t_i18n }) => {
      const classes = useStyles();
      return (
        <Chip
          classes={{ root: classes.chipInList }}
          color="primary"
          variant="outlined"
          label={incident_type || t_i18n('Unknown')}
        />
      );
    },
  },
  infrastructure_types: {
    id: 'infrastructure_types',
    label: 'Type',
    flexSize: 8,
    isSortable: true,
    render: ({ infrastructure_types }, { t_i18n }) => {
      const classes = useStyles();
      return (
        <Chip
          classes={{ root: classes.chipInList }}
          color="primary"
          variant="outlined"
          label={infrastructure_types?.at(0) ?? t_i18n('Unknown')}
        />
      );
    },
  },
  is_family: {
    id: 'is_family',
    label: 'Is family',
    flexSize: 8,
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
    flexSize: 8,
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
    flexSize: 15,
    isSortable: false,
    render: ({ killChainPhases }) => ((killChainPhases && killChainPhases.length > 0)
      ? `[${killChainPhases[0].kill_chain_name}] ${killChainPhases[0].phase_name}`
      : '-'),
  },
  last_observed: {
    id: 'last_observed',
    label: 'Last obs.',
    flexSize: 14,
    isSortable: true,
    render: ({ last_observed }, { nsdt }) => nsdt(last_observed),
  },
  last_seen: {
    id: 'last_seen',
    label: 'Last obs.',
    flexSize: 12,
    isSortable: true,
    render: ({ last_seen }, { nsdt }) => nsdt(last_seen),
  },
  malware_types: {
    id: 'malware_types',
    label: 'Malware types',
    flexSize: 15,
    isSortable: true,
    render: ({ malware_types }, { column: { size } }) => {
      const value = malware_types ? malware_types.join(', ') : '-';
      return (<Tooltip title={value}><div>{truncate(value, size * MAGICAL_SIZE)}</div></Tooltip>);
    },
  },
  modified: {
    id: 'modified',
    label: 'Modification date',
    flexSize: 15,
    isSortable: true,
    render: ({ modified }, { fd }) => fd(modified),
  },
  name: {
    id: 'name',
    label: 'Name',
    flexSize: 25,
    isSortable: true,
    render: (data, { column: { size } }) => (
      <Tooltip title={getMainRepresentative(data)}>
        <div>{truncate(getMainRepresentative(data), size * MAGICAL_SIZE)}</div>
      </Tooltip>
    ),
  },
  note_types: {
    id: 'note_types',
    label: 'Type',
    flexSize: 10,
    isSortable: true,
    render: ({ note_types }, { t_i18n }) => {
      const classes = useStyles();
      return (
        <Chip
          classes={{ root: classes.chipInList }}
          color="primary"
          variant="outlined"
          label={note_types?.at(0) ?? t_i18n('Unknown')}
        />
      );
    },
  },
  number_observed: {
    id: 'number_observed',
    label: 'Nb.',
    flexSize: 8,
    isSortable: true,
    render: ({ number_observed }, { n }) => (<Tooltip title={number_observed}><>{n(number_observed)}</></Tooltip>),
  },
  objectAssignee: {
    id: 'objectAssignee',
    label: 'Assignees',
    flexSize: 10,
    isSortable: false,
    render: ({ objectAssignee }, { column: { size } }) => {
      const value = isNotEmptyField(objectAssignee) ? objectAssignee.map((c: { name: string }) => c.name).join(', ') : '-';
      return (<Tooltip title={value}><div>{truncate(value, size * MAGICAL_SIZE)}</div></Tooltip>);
    },
  },
  objectLabel: {
    id: 'objectLabel',
    label: 'Labels',
    flexSize: 15,
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
    flexSize: 8,
    isSortable: true,
    render: ({ objectMarking }) => (
      <ItemMarkings
        variant="inList"
        markingDefinitions={objectMarking ?? []}
        limit={1}
      />
    ),
  },
  observable_value: {
    id: 'observable_value',
    label: 'Value',
    flexSize: 20,
    isSortable: false,
    render: ({ observable_value }, { column: { size } }) => (
      <Tooltip title={observable_value}><div>{truncate(observable_value, size * MAGICAL_SIZE)}</div></Tooltip>
    ),
  },
  operatingSystem: {
    id: 'operatingSystem',
    label: 'Operating System',
    flexSize: 15,
    isSortable: false,
    render: ({ operatingSystem }) => (<Tooltip title={operatingSystem?.name}><>{operatingSystem?.name ?? '-'}</></Tooltip>),
  },
  owner: {
    id: 'owner',
    label: 'Owner',
    flexSize: 12,
    isSortable: true,
    render: ({ owner }, h) => textInTooltip(owner.name, h),
  },
  pattern_type: {
    id: 'pattern_type',
    label: 'Pattern type',
    flexSize: 10,
    isSortable: true,
    render: ({ pattern_type }) => (<ItemPatternType variant="inList" label={pattern_type} />),
  },
  primary_motivation: {
    id: 'primary_motivation',
    label: 'Primary motivation',
    flexSize: 10,
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
    flexSize: 10,
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
    flexSize: 15,
    isSortable: true,
    render: ({ product }, { column: { size } }) => (
      <Tooltip title={product}><div>{truncate(product, size * MAGICAL_SIZE)}</div></Tooltip>
    ),
  },
  published: {
    id: 'published',
    label: 'Date',
    flexSize: 10,
    isSortable: true,
    render: ({ published }, { fd }) => fd(published),
  },
  rating: {
    id: 'rating',
    label: 'Rating',
    flexSize: 10,
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
    flexSize: 10,
    isSortable: true,
    render: ({ relationship_type }, { t_i18n }) => {
      const classes = useStyles();
      return (
        <Chip
          classes={{ root: classes.chipInList }}
          color="primary"
          variant="outlined"
          label={relationship_type ?? t_i18n('Unknown')}
        />
      );
    },
  },
  report_types: {
    id: 'report_types',
    label: 'Type',
    flexSize: 10,
    isSortable: true,
    render: ({ report_types }, { t_i18n }) => {
      const classes = useStyles();
      return (
        <Chip
          classes={{ root: classes.chipInList }}
          color="primary"
          variant="outlined"
          label={report_types?.at(0) ?? t_i18n('Unknown')}
        />
      );
    },
  },
  resource_level: {
    id: 'resource_level',
    label: 'Resource level',
    flexSize: 10,
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
    flexSize: 15,
    isSortable: true,
    render: ({ result_name }, { column: { size } }) => (
      <Tooltip title={result_name}><div>{truncate(result_name, size * MAGICAL_SIZE)}</div></Tooltip>
    ),
  },
  secondary_motivations: {
    id: 'secondary_motivations',
    label: 'Secondary motivations',
    flexSize: 10,
    isSortable: false,
    render: ({ secondary_motivations }, { column: { size } }) => {
      const value = secondary_motivations ? secondary_motivations.join(', ') : '-';
      return (<Tooltip title={value}><div>{truncate(value, size * MAGICAL_SIZE)}</div></Tooltip>);
    },
  },
  severity: {
    id: 'severity',
    label: 'Severity',
    flexSize: 10,
    isSortable: true,
    render: ({ severity }, { t_i18n }) => (
      <ItemPriority
        variant="inList"
        priority={severity}
        label={severity || t_i18n('Unknown')}
      />
    ),
  },
  sophistication: {
    id: 'sophistication',
    label: 'Sophistication',
    flexSize: 10,
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
    flexSize: 15,
    isSortable: true,
    render: ({ source_name }, { column: { size } }) => (
      <Tooltip title={source_name}><div>{truncate(source_name, size * MAGICAL_SIZE)}</div></Tooltip>
    ),
  },
  start_time: {
    id: 'start_time',
    label: 'Start date',
    flexSize: 15,
    isSortable: true,
    render: ({ start_time }, { fd }) => fd(start_time),
  },
  stop_time: {
    id: 'stop_time',
    label: 'End date',
    flexSize: 15,
    isSortable: true,
    render: ({ stop_time }, { fd }) => fd(stop_time),
  },
  submitted: {
    id: 'submitted',
    label: 'Submission date',
    flexSize: 12,
    isSortable: true,
    render: ({ submitted }, { fd }) => fd(submitted),
  },
  tags: {
    id: 'tags',
    label: 'Tags',
    flexSize: 15,
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
            <Chip label='...' style={chipStyle} />
          </div>
        </Tooltip>
      );
    },
  },
  threat_actor_types: {
    id: 'threat_actor_types',
    label: 'Types',
    flexSize: 20,
    isSortable: true,
    render: ({ threat_actor_types }, { column: { size } }) => {
      const value = threat_actor_types ? threat_actor_types.join(', ') : '-';
      return (<Tooltip title={value}><div>{truncate(value, size * MAGICAL_SIZE)}</div></Tooltip>);
    },
  },
  toName: {
    id: 'toName',
    label: 'To name',
    flexSize: 18,
    isSortable: false,
    render: ({ to }, { column: { size }, t_i18n }) => {
      const value = to ? getMainRepresentative(to) : t_i18n('Restricted');
      return (<Tooltip title={value}><div>{truncate(value, size * MAGICAL_SIZE)}</div></Tooltip>);
    },
  },
  updated_at: {
    id: 'updated_at',
    label: 'Modification date',
    flexSize: 15,
    isSortable: true,
    render: ({ updated_at }, { fd }) => fd(updated_at),
  },
  url: {
    id: 'url',
    label: 'URL',
    flexSize: 45,
    isSortable: true,
    render: ({ url }, { column: { size } }) => (<Tooltip title={url}><div>{truncate(url, size * MAGICAL_SIZE)}</div></Tooltip>),
  },
  user_email: {
    id: 'user_email',
    label: 'Email',
    flexSize: 50,
    isSortable: false,
    render: ({ user_email }, { column: { size } }) => (
      <Tooltip title={user_email}><div>{truncate(user_email, size * MAGICAL_SIZE)}</div></Tooltip>
    ),
  },
  value: {
    id: 'value',
    label: 'Value',
    flexSize: 22,
    isSortable: false,
    render: (node, { column: { size } }) => {
      const value = getMainRepresentative(node);
      return (<Tooltip title={value}><div>{truncate(value, size * MAGICAL_SIZE)}</div></Tooltip>);
    },
  },
  x_mitre_id: {
    id: 'x_mitre_id',
    label: 'ID',
    flexSize: 10,
    isSortable: true,
    render: ({ x_mitre_id }) => <code>{emptyFilled(x_mitre_id)}</code>,
  },
  x_opencti_negative: {
    id: 'x_opencti_negative',
    label: 'Qualification',
    flexSize: 15,
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
    flexSize: 15,
    isSortable: true,
    render: ({ x_opencti_cvss_base_severity }) => (
      <Tooltip title={x_opencti_cvss_base_severity}><>{x_opencti_cvss_base_severity}</></Tooltip>
    ),
  },
  x_opencti_organization_type: {
    id: 'x_opencti_organization_type',
    label: 'Type',
    flexSize: 15,
    isSortable: true,
    render: ({ x_opencti_organization_type }) => {
      const classes = useStyles();
      return (
        <Chip
          classes={{ root: classes.chipInList }}
          color="primary"
          variant="outlined"
          label={x_opencti_organization_type ?? 'Unknown'}
        />
      );
    },
  },
  x_opencti_workflow_id: {
    id: 'x_opencti_workflow_id',
    label: 'Status',
    flexSize: 8,
    isSortable: true,
    render: ({ status, workflowEnabled }, { variant }) => (
      <ItemStatus
        status={status}
        variant={variant === DataTableVariant.default ? 'inList' : 'inLine'}
        disabled={!workflowEnabled}
      />
    ),
  },
};

export const defaultColumnsMap = new Map<string, Partial<DataTableColumn>>(Object.entries(defaultColumns));
