import React, { ReactNode } from 'react';
import Chip from '@mui/material/Chip';
import makeStyles from '@mui/styles/makeStyles';
import StixCoreObjectLabels from '@components/common/stix_core_objects/StixCoreObjectLabels';
import Tooltip from '@mui/material/Tooltip';
import { Link } from 'react-router-dom';
import { useTheme } from '@mui/styles';
import { DraftChip } from '@components/common/draft/DraftChip';
import { HorizontalRule, Security } from '@mui/icons-material';
import ItemCvssScore from '../ItemCvssScore';
import type { DataTableColumn } from './dataTableTypes';
import { DataTableProps, DataTableVariant } from './dataTableTypes';
import ItemMarkings from '../ItemMarkings';
import ItemStatus from '../ItemStatus';
import { emptyFilled } from '../../utils/String';
import ItemPriority from '../ItemPriority';
import { isNotEmptyField } from '../../utils/utils';
import RatingField from '../fields/RatingField';
import ItemConfidence from '../ItemConfidence';
import ItemPatternType from '../ItemPatternType';
import type { Theme } from '../Theme';
import { getMainRepresentative } from '../../utils/defaultRepresentatives';
import ItemEntityType from '../ItemEntityType';
import ItemScore from '../ItemScore';
import ItemOpenVocab from '../ItemOpenVocab';
import ItemBoolean from '../ItemBoolean';
import ItemSeverity from '../ItemSeverity';
import ItemOperations from '../ItemOperations';
import ItemDueDate from '../ItemDueDate';
import { APP_BASE_PATH } from '../../relay/environment';
import FieldOrEmpty from '../FieldOrEmpty';

const chipStyle = {
  fontSize: '12px',
  lineHeight: '12px',
  height: '20px',
  marginRight: '7px',
  borderRadius: '10px',
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

export const Truncate = ({ children }: { children: ReactNode }) => (
  <div style={{ textOverflow: 'ellipsis', overflow: 'hidden', whiteSpace: 'nowrap' }}>
    {children}
  </div>
);

export const defaultRender: NonNullable<DataTableColumn['render']> = (data, displayDraftChip = false) => {
  return (
    <FieldOrEmpty source={data}>
      <Tooltip title={data}>
        <div style={{ maxWidth: '100%', display: 'flex' }}>
          <Truncate>{data}</Truncate>
          {displayDraftChip && (<DraftChip/>)}
        </div>
      </Tooltip>
    </FieldOrEmpty>
  );
};

const defaultColumns: DataTableProps['dataColumns'] = {
  aliases: {
    id: 'aliases',
    label: 'Aliases',
    percentWidth: 10,
    render: ({ aliases }) => {
      const theme = useTheme<Theme>();

      return aliases ? (
        <Tooltip title={aliases.join(', ')}>
          <div style={{ maxWidth: '100%', display: 'flex', gap: theme.spacing(0.5) }}>
            {aliases.map((value: string) => (<Chip key={value} label={value} size="small" />))}
          </div>
        </Tooltip>
      ) : defaultRender('-');
    },
  },
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
      />
    ),
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
  authorized_members_activation_date: {
    id: 'authorized_members_activation_date',
    label: 'Restriction Date',
    isSortable: true,
    render: ({ authorized_members_activation_date }, helpers) => defaultRender(helpers.fd(authorized_members_activation_date)),
  },
  attribute_abstract: {
    id: 'attribute_abstract',
    label: 'Abstract',
    percentWidth: 25,
    isSortable: true,
    render: ({ attribute_abstract, content, draftVersion }) => {
      return defaultRender(attribute_abstract || content, draftVersion);
    },
  },
  attribute_count: {
    id: 'attribute_count',
    label: 'Nb.',
    percentWidth: 4,
    isSortable: true,
    render: ({ attribute_count }) => defaultRender(String(attribute_count)),
  },
  channel_types: {
    id: 'channel_types',
    label: 'Types',
    percentWidth: 20,
    isSortable: true,
    render: ({ channel_types }) => {
      const value = isNotEmptyField(channel_types) ? channel_types.join(', ') : '-';
      return defaultRender(value);
    },
  },
  color: {
    id: 'color',
    label: 'Color',
    percentWidth: 25,
    isSortable: true,
    render: ({ color }) => (
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
          <Truncate>{color}</Truncate>
        </>
      </Tooltip>
    ),
  },
  usages: {
    id: 'usages',
    label: 'Usages',
    percentWidth: 20,
    isSortable: false,
    render: ({ usages }) => {
      const value = usages != null ? usages : '-';
      return defaultRender(value);
    },
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
    render: ({ created }, helpers) => defaultRender(helpers.fd(created)),
  },
  created_at: {
    id: 'created_at',
    label: 'Platform creation date',
    percentWidth: 15,
    isSortable: true,
    render: ({ created_at }, helpers) => defaultRender(helpers.fd(created_at)),
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
    render: ({ creators }) => {
      const value = isNotEmptyField(creators) ? creators.map((c: { name: string }) => c.name).join(', ') : '-';
      return defaultRender(value);
    },
  },
  creators: {
    id: 'creators',
    label: 'Creators',
    percentWidth: 12,
    render: ({ creators }) => {
      const value = isNotEmptyField(creators) ? creators.map((c: { name: string }) => c.name).join(', ') : '-';
      return defaultRender(value);
    },
  },
  definition: {
    id: 'definition',
    label: 'Definition',
    percentWidth: 25,
    isSortable: true,
    render: ({ definition }) => defaultRender(definition),
  },
  definition_type: {
    id: 'definition_type',
    label: 'Type',
    percentWidth: 25,
    isSortable: true,
    render: ({ definition_type }) => defaultRender(definition_type),
  },
  description: {
    id: 'description',
    label: 'Description',
    percentWidth: 25,
    isSortable: true,
    render: ({ description }) => defaultRender(description),
  },
  draftVersion: {
    id: 'draftVersion',
    label: 'Operation',
    percentWidth: 10,
    isSortable: false,
    render: ({ draftVersion }) => (
      <ItemOperations
        draftOperation={draftVersion?.draft_operation}
      />
    ),
  },
  effective_confidence_level: {
    id: 'effective_confidence_level',
    label: 'Max Confidence',
    percentWidth: 10,
    isSortable: false,
    render: ({ effective_confidence_level }) => defaultRender(effective_confidence_level?.max_confidence),
  },
  entity_type: {
    id: 'entity_type',
    label: 'Type',
    percentWidth: 10,
    isSortable: false,
    render: (data) => <ItemEntityType showIcon entityType={data.entity_type} inList />,
  },
  entity_types: {
    id: 'entity_types',
    label: 'Used in',
    percentWidth: 20,
    isSortable: false,
    render: (data, { t_i18n }) => (
      <>
        {data.category.entity_types?.map((type: string) => (
          <Tooltip key={`entity_${type}`} title={t_i18n(`entity_${type}`)}>
            <div style={{
              float: 'left',
              marginRight: 7,
              overflow: 'hidden',
              whiteSpace: 'nowrap' }}
            >
              <Chip
                key={type}
                style={{
                  fontSize: 12,
                  height: 20,
                }}
                variant="outlined"
                label={t_i18n(`entity_${type}`)}
                color="primary"
              />
            </div>
          </Tooltip>
        ))}
      </>
    ),
  },
  event_types: {
    id: 'event_types',
    label: 'Types',
    percentWidth: 20,
    isSortable: true,
    render: ({ event_types }) => {
      const value = isNotEmptyField(event_types) ? event_types.join(', ') : '-';
      return defaultRender(value);
    },
  },
  due_date: {
    id: 'due_date',
    label: 'Due Date',
    percentWidth: 15,
    render: ({ due_date }) => <ItemDueDate due_date={due_date} variant={'inList'} />,
  },
  external_id: {
    id: 'external_id',
    label: 'External ID',
    percentWidth: 10,
    isSortable: true,
    render: ({ external_id }) => defaultRender(external_id),
  },
  file_name: {
    id: 'file_name',
    label: 'File name',
    percentWidth: 12,
    isSortable: false,
    render: (data) => {
      const file = (data.importFiles?.edges && data.importFiles.edges.length > 0)
        ? data.importFiles.edges[0]?.node
        : { name: 'N/A', metaData: { mimetype: 'N/A' }, size: 0 };
      return (
        <Tooltip title={file?.name}>
          <Truncate>{file?.name}</Truncate>
        </Tooltip>
      );
    },
  },
  file_mime_type: {
    id: 'file_mime_type',
    label: 'Mime/Type',
    percentWidth: 8,
    isSortable: false,
    render: (data) => {
      const file = (data.importFiles?.edges && data.importFiles.edges.length > 0)
        ? data.importFiles.edges[0]?.node
        : { name: 'N/A', metaData: { mimetype: 'N/A' }, size: 0 };
      return (
        <Tooltip title={file?.metaData?.mimetype}>
          <Truncate>{file?.metaData.mimetype}</Truncate>
        </Tooltip>
      );
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
      return (
        <Tooltip title={file?.metaData?.mimetype}>
          <>{b(file?.size)}</>
        </Tooltip>
      );
    },
  },
  firstname: {
    id: 'firstname',
    label: 'Firstname',
    percentWidth: 10,
    isSortable: true,
    render: ({ firstname }) => defaultRender(firstname),
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
      const displayDraftChip = !!from?.draftVersion;
      return defaultRender(value, displayDraftChip);
    },
  },
  from_created_at: {
    id: 'from_created_at',
    label: 'Platform creation date',
    percentWidth: 15,
    isSortable: true,
    render: ({ from }, helpers) => {
      const { created_at } = from;
      return defaultRender(helpers.fd(created_at));
    },
  },
  from_creator: {
    id: 'from_creator',
    label: 'Source Creators',
    percentWidth: 12,
    render: ({ from }) => {
      const { creators } = from;
      const value = isNotEmptyField(creators) ? creators.map((c: { name: string }) => c.name).join(', ') : '-';
      return defaultRender(value);
    },
  },
  from_entity_type: {
    id: 'from_entity_type',
    label: 'Source type',
    percentWidth: 10,
    render: ({ from }) => (<ItemEntityType showIcon entityType={from?.entity_type} inList />),
  },
  from_objectLabel: {
    id: 'from_objectLabel',
    label: 'Source Labels',
    percentWidth: 15,
    isSortable: false,
    render: ({ from }) => {
      const { objectLabel } = from;
      return (
        <StixCoreObjectLabels
          variant="inList"
          labels={objectLabel}
        />
      );
    },
  },
  from_objectMarking: {
    id: 'from_objectMarking',
    label: 'Marking',
    percentWidth: 8,
    isSortable: true,
    render: ({ from }, { storageHelpers: { handleAddFilter } }) => {
      const { objectMarking } = from;
      return (
        <ItemMarkings
          variant="inList"
          markingDefinitions={objectMarking ?? []}
          limit={1}
          onClick={(m) => handleAddFilter('objectMarking', m.id, 'eq')}
        />
      );
    },
  },
  from_relationship_type: {
    id: 'from_relationship_type',
    label: 'Source name',
    percentWidth: 10,
    render: ({ from }, helpers) => {
      const value = from ? getMainRepresentative(from) : helpers.t_i18n('Restricted');
      return defaultRender(value);
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
  response_types: {
    id: 'response_types',
    label: 'Response type',
    percentWidth: 9,
    isSortable: true,
    render: ({ response_types }, { t_i18n, storageHelpers: { handleAddFilter } }) => {
      const classes = useStyles();
      return (
        <Chip
          classes={{ root: classes.chipInList }}
          color="primary"
          variant="outlined"
          label={response_types?.at(0) ?? t_i18n('Unknown')}
          onClick={(e) => {
            e.preventDefault();
            e.stopPropagation();
            handleAddFilter('response_types', response_types?.at(0) ?? null, 'eq');
          }}
        />
      );
    },
  },
  information_types: {
    id: 'information_types',
    label: 'Information type',
    percentWidth: 9,
    isSortable: true,
    render: ({ information_types }, { t_i18n, storageHelpers: { handleAddFilter } }) => {
      const classes = useStyles();
      return (
        <Chip
          classes={{ root: classes.chipInList }}
          color="primary"
          variant="outlined"
          label={information_types?.at(0) ?? t_i18n('Unknown')}
          onClick={(e) => {
            e.preventDefault();
            e.stopPropagation();
            handleAddFilter('information_types', information_types?.at(0) ?? null, 'eq');
          }}
        />
      );
    },
  },
  takedown_types: {
    id: 'takedown_types',
    label: 'Takedown type',
    percentWidth: 9,
    isSortable: true,
    render: ({ takedown_types }, { t_i18n, storageHelpers: { handleAddFilter } }) => {
      const classes = useStyles();
      return (
        <Chip
          classes={{ root: classes.chipInList }}
          color="primary"
          variant="outlined"
          label={takedown_types?.at(0) ?? t_i18n('Unknown')}
          onClick={(e) => {
            e.preventDefault();
            e.stopPropagation();
            handleAddFilter('takedown_types', takedown_types?.at(0) ?? null, 'eq');
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
    label: 'Publicly shared',
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
    render: ({ killChainPhases }) => {
      const formattedKillChainPhase = (killChainPhases && killChainPhases.length > 0)
        ? `[${killChainPhases[0].kill_chain_name}] ${killChainPhases[0].phase_name}`
        : '-';
      return defaultRender(formattedKillChainPhase);
    },
  },
  kill_chain_name: {
    id: 'kill_chain_name',
    label: 'Kill chain name',
    percentWidth: 40,
    isSortable: true,
    render: ({ kill_chain_name }) => defaultRender(kill_chain_name),
  },
  lastname: {
    id: 'lastname',
    label: 'Lastname',
    percentWidth: 10,
    isSortable: true,
    render: ({ lastname }) => defaultRender(lastname),
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
    render: ({ malware_types }) => {
      const value = malware_types ? malware_types.join(', ') : '-';
      return defaultRender(value);
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
    render: (data) => {
      const displayDraftChip = !!data.draftVersion;
      return defaultRender(getMainRepresentative(data), displayDraftChip);
    },
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
  tool_types: {
    id: 'tool_types',
    label: 'Type',
    percentWidth: 10,
    isSortable: true,
    render: ({ tool_types }, { t_i18n, storageHelpers: { handleAddFilter } }) => {
      const classes = useStyles();
      return (
        <Chip
          classes={{ root: classes.chipInList }}
          color="primary"
          variant="outlined"
          label={tool_types?.at(0) ?? t_i18n('Unknown')}
          onClick={(e) => {
            e.preventDefault();
            e.stopPropagation();
            handleAddFilter('tool_types', tool_types?.at(0) ?? null, 'eq');
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
    render: ({ objectAssignee }) => {
      const value = isNotEmptyField(objectAssignee) ? objectAssignee.map((c: { name: string }) => c.name).join(', ') : '-';
      return defaultRender(value);
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
        onClick={(m) => handleAddFilter('objectMarking', m.id, 'eq')}
      />
    ),
  },
  objectParticipant: {
    id: 'objectParticipant',
    label: 'Participant',
    percentWidth: 10,
    render: ({ objectParticipant }) => {
      const value = isNotEmptyField(objectParticipant) ? objectParticipant.map((c: { name: string }) => c.name).join(', ') : '-';
      return defaultRender(value);
    },
  },
  observable_value: {
    id: 'observable_value',
    label: 'Value',
    percentWidth: 20,
    isSortable: false,
    // Please check the String.jsx->renderObservableValue. It should have the same behavior and will replace it at the end.
    render: (observable) => {
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
                    {defaultRender(observable.observable_value, observable.draftVersion)}
                  </div>
                </div>
              );
            }
          }
          return defaultRender(observable.observable_value, observable.draftVersion);
        }
        default:
          return defaultRender(observable.observable_value, observable.draftVersion);
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
  opinions_metrics_mean: {
    id: 'opinions_metrics_mean',
    label: 'Opinions mean',
    percentWidth: 10,
    render: ({ opinions_metrics }) => <span style={{ fontWeight: 700, fontSize: 15 }}>{opinions_metrics?.mean ?? '-'}</span>,
  },
  order: {
    id: 'order',
    label: 'Order',
    percentWidth: 10,
    isSortable: true,
    render: ({ order }, { n }) => defaultRender(n(order)),
  },
  otp: {
    id: 'otp',
    label: '2FA',
    percentWidth: 5,
    isSortable: false,
    render: (user) => (
      <>
        {user.otp_activated ? (
          <Security fontSize="small" color="secondary" />
        ) : (
          <HorizontalRule fontSize="small" color="primary" />
        )}
      </>
    ),
  },
  owner: {
    id: 'owner',
    label: 'Owner',
    percentWidth: 12,
    isSortable: true,
    render: ({ owner }) => defaultRender(owner.name),
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
    render: ({ phase_name }) => defaultRender(phase_name),
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
    render: ({ product }) => defaultRender(product),
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
    render: ({ result_name, draftVersion }) => defaultRender(result_name, draftVersion),
  },
  secondary_motivations: {
    id: 'secondary_motivations',
    label: 'Secondary motivations',
    percentWidth: 10,
    isSortable: false,
    render: ({ secondary_motivations }) => {
      const value = secondary_motivations ? secondary_motivations.join(', ') : '-';
      return defaultRender(value);
    },
  },
  security_platform_type: {
    id: 'security_platform_type',
    label: 'Type',
    percentWidth: 20,
    isSortable: true,
    render: ({ security_platform_type }) => {
      const value = isNotEmptyField(security_platform_type) ? security_platform_type : '-';
      return defaultRender(value);
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
    render: ({ source_name, draftVersion }) => defaultRender(source_name, draftVersion),
  },
  start_date: {
    id: 'start_date',
    label: 'Start date',
    percentWidth: 25,
    isSortable: true,
    render: ({ start_date }, { fd }) => fd(start_date),
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
    render: ({ threat_actor_types }) => {
      const value = isNotEmptyField(threat_actor_types) ? threat_actor_types.join(', ') : '-';
      return defaultRender(value);
    },
  },
  toName: {
    id: 'toName',
    label: 'To name',
    percentWidth: 18,
    isSortable: false,
    render: ({ to }, helpers) => {
      const value = to ? getMainRepresentative(to) : helpers.t_i18n('Restricted');
      const displayDraftChip = !!to?.draftVersion;
      return defaultRender(value, displayDraftChip);
    },
  },
  to_entity_type: {
    id: 'to_entity_type',
    label: 'Target type',
    percentWidth: 10,
    render: ({ to }) => (<ItemEntityType showIcon entityType={to?.entity_type} inList />),
  },
  to_relationship_type: {
    id: 'to_relationship_type',
    label: 'Target name',
    percentWidth: 10,
    render: ({ to }, helpers) => {
      const value = to ? getMainRepresentative(to) : helpers.t_i18n('Restricted');
      return defaultRender(value);
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
    render: ({ url }) => defaultRender(url),
  },
  user_email: {
    id: 'user_email',
    label: 'Email',
    percentWidth: 50,
    isSortable: false,
    render: ({ user_email }) => defaultRender(user_email),
  },
  valid_until: {
    id: 'valid_until',
    label: 'Valid until',
    percentWidth: 10,
    isSortable: true,
    render: ({ valid_until }, { nsdt }) => <Tooltip title={nsdt(valid_until)}>{nsdt(valid_until)}</Tooltip>,
  },
  valid_from: {
    id: 'valid_from',
    label: 'Valid from',
    percentWidth: 10,
    isSortable: true,
    render: ({ valid_from }, { nsdt }) => <Tooltip title={nsdt(valid_from)}>{nsdt(valid_from)}</Tooltip>,
  },
  value: {
    id: 'value',
    label: 'Value',
    percentWidth: 22,
    isSortable: false,
    render: (node) => {
      const value = getMainRepresentative(node);
      const displayDraftChip = !!node.draftVersion;
      return defaultRender(value, displayDraftChip);
    },
  },
  x_mitre_id: {
    id: 'x_mitre_id',
    label: 'ID',
    percentWidth: 10,
    isSortable: true,
    render: ({ x_mitre_id }) => <code>{emptyFilled(x_mitre_id)}</code>,
  },
  x_opencti_color: {
    id: 'x_opencti_color',
    label: 'Color',
    percentWidth: 15,
    isSortable: true,
    render: ({ x_opencti_color }) => (
      <Tooltip title={x_opencti_color}>
        <>
          <div
            style={{
              backgroundColor: x_opencti_color,
              height: 20,
              width: 20,
              display: 'inline-flex',
              borderRadius: 20,
              marginRight: 5,
            }}
          />
          <Truncate>{x_opencti_color}</Truncate>
        </>
      </Tooltip>
    ),
  },
  x_opencti_order: {
    id: 'x_opencti_order',
    label: 'Order',
    percentWidth: 10,
    isSortable: true,
    render: ({ x_opencti_order }) => defaultRender(x_opencti_order.toString()),
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
  x_opencti_cvss_base_score: {
    id: 'x_opencti_cvss_base_score',
    label: 'CVSS3 - Score',
    percentWidth: 15,
    render: ({ x_opencti_cvss_base_score }) => {
      const value = x_opencti_cvss_base_score ? Math.trunc(x_opencti_cvss_base_score * 10) / 10 : null;
      return <ItemCvssScore score={value} />;
    },
  },
  x_opencti_cvss_v4_base_score: {
    id: 'x_opencti_cvss_v4_base_score',
    label: 'CVSS4 - Score',
    percentWidth: 15,
    render: ({ x_opencti_cvss_v4_base_score }) => {
      const value = x_opencti_cvss_v4_base_score ? Math.trunc(x_opencti_cvss_v4_base_score * 10) / 10 : null;
      return <ItemCvssScore score={value} />;
    },
  },
  x_opencti_cisa_kev: {
    id: 'x_opencti_cisa_kev',
    label: 'CISA KEV',
    percentWidth: 15,
    render: ({ x_opencti_cisa_kev }, { t_i18n }) => (
      <ItemBoolean
        status={x_opencti_cisa_kev}
        label={x_opencti_cisa_kev ? t_i18n('Yes') : t_i18n('No')}
      />
    ),
  },
  x_opencti_epss_score: {
    id: 'x_opencti_epss_score',
    label: 'EPSS Score',
    percentWidth: 15,
    render: ({ x_opencti_epss_score }) => {
      const value = x_opencti_epss_score ? Math.trunc(x_opencti_epss_score * 100000) / 100000 : '-';
      return defaultRender(value);
    },
  },
  x_opencti_epss_percentile: {
    id: 'x_opencti_epss_percentile',
    label: 'EPSS Percentile',
    percentWidth: 15,
    render: ({ x_opencti_epss_percentile }) => {
      const value = x_opencti_epss_percentile ? Math.trunc(x_opencti_epss_percentile * 100000) / 100000 : '-';
      return defaultRender(value);
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
  x_opencti_cvss_v4_base_severity: {
    id: 'x_opencti_cvss_v4_base_severity',
    label: 'CVSS4 - Severity',
    percentWidth: 15,
    isSortable: true,
    render: ({ x_opencti_cvss_v4_base_severity }, { t_i18n }) => (
      <ItemSeverity
        severity={x_opencti_cvss_v4_base_severity}
        label={x_opencti_cvss_v4_base_severity || t_i18n('Unknown')}
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
          label={x_opencti_organization_type || 'Unknown'}
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
  x_opencti_aliases: {
    id: 'x_opencti_aliases',
    label: 'Aliases',
    percentWidth: 10,
    render: ({ x_opencti_aliases, entity_type }) => {
      const theme = useTheme<Theme>();

      if (!x_opencti_aliases) {
        return defaultRender('-');
      }
      if (entity_type === 'Country') {
        const flag = x_opencti_aliases.filter((n: string) => n.length === 2)[0];
        if (flag) {
          return (
            <div style={{ display: 'flex', gap: theme.spacing(1), alignItems: 'center' }}>
              <Tooltip title={x_opencti_aliases}>
                <img
                  style={{ width: 20 }}
                  src={`${APP_BASE_PATH}/static/flags/4x3/${flag.toLowerCase()}.svg`}
                  alt={x_opencti_aliases}
                />
              </Tooltip>
              <div>
                {x_opencti_aliases[0]}
              </div>
            </div>
          );
        }
      }

      return (
        <Tooltip title={x_opencti_aliases.join(', ')}>
          <div style={{ maxWidth: '100%', display: 'flex', gap: theme.spacing(0.5) }}>
            {x_opencti_aliases.map((value: string) => (<Chip key={value} label={value} size="small" />))}
          </div>
        </Tooltip>
      );
    },
  },
  x_opencti_score: {
    id: 'x_opencti_score',
    label: 'Score',
    percentWidth: 10,
    isSortable: true,
    render: ({ x_opencti_score }) => <ItemScore score={x_opencti_score} />,
  },
};

export const defaultColumnsMap = new Map<string, Partial<DataTableColumn>>(Object.entries(defaultColumns));
