import React, { FunctionComponent } from 'react';
import { Box, List, ListItem, Stack, Typography } from '@mui/material';
import { useTheme } from '@mui/styles';
import type { Theme } from '../../../components/Theme';
import { useFormatter } from '../../../components/i18n';
import type { WidgetColumn } from '../../../utils/widget/widget';
import ItemMarkings from '../../../components/ItemMarkings';
import ItemAuthor from '../../../components/ItemAuthor';
import ItemConfidence from '../../../components/ItemConfidence';
import ItemBoolean from '../../../components/ItemBoolean';
import ItemCreators from '../../../components/ItemCreators';
import ItemOpenVocab from '../../../components/ItemOpenVocab';
import ItemStatus from '../../../components/ItemStatus';
import ItemPatternType from '../../../components/ItemPatternType';
import ItemAssignees from '../../../components/ItemAssignees';
import ItemParticipants from '../../../components/ItemParticipants';
import ExpandableMarkdown from '../../../components/ExpandableMarkdown';
import FieldOrEmpty from '../../../components/FieldOrEmpty';
import Tag from '@common/tag/Tag';
import { StixCoreObjectsCustomAttributesQuery$data } from '@components/common/stix_core_objects/__generated__/StixCoreObjectsCustomAttributesQuery.graphql';
import { entityTypeRenderers } from '../../../utils/widget/widgetCustomAttributesRendererUtils';
import ListItemText from '@mui/material/ListItemText';

export type StixCoreObject = NonNullable<StixCoreObjectsCustomAttributesQuery$data['stixCoreObject']>;

interface WidgetCustomAttributesCardProps {
  column: WidgetColumn;
  data: StixCoreObject | null | undefined;
  isCustomViewReadOnly?: boolean;
}

const renderAttributeValue = (
  attribute: string,
  data: StixCoreObject | null | undefined,
  t_i18n: (s: string) => string,
  fldt: (s: unknown) => string,
) => {
  const entityType = data?.entity_type ?? '';
  if (!data) {
    return (
      <Typography variant="body2" sx={{ color: 'text.disabled', fontStyle: 'italic' }}>
        —
      </Typography>
    );
  }

  const specificRenderer = entityTypeRenderers[entityType]?.[attribute];
  if (specificRenderer) {
    return specificRenderer(data, t_i18n, fldt);
  }

  switch (attribute) {
    case 'objectMarking':
      return (
        <ItemMarkings
          markingDefinitions={data.objectMarking ?? []}
        />
      );
    case 'createdBy':
      return <ItemAuthor createdBy={data.createdBy ?? null} />;
    case 'confidence':
      return (
        <ItemConfidence
          confidence={data.confidence ?? null}
          entityType={entityType}
        />
      );
    case 'objectLabel': {
      const labels = data.objectLabel as
        | { id: string; value: string; color: string }[]
        | undefined;
      return (
        <FieldOrEmpty source={labels}>
          <Stack direction="row" flexWrap="wrap" gap={1}>
            {labels?.map((label) => (
              <Tag
                key={label.id}
                label={label.value}
                color={label.color}
              />
            ))}
          </Stack>
        </FieldOrEmpty>
      );
    }
    case 'creators':
      return <ItemCreators creators={data.creators ?? []} />;
    case 'objectAssignee': {
      const assignees = 'objectAssignee' in data
        ? (data as { objectAssignee?: { id: string; name: string; entity_type: string }[] }).objectAssignee ?? []
        : [];
      return (
        <ItemAssignees
          assignees={assignees}
          stixDomainObjectId={data.id}
        />
      );
    }
    case 'objectParticipant': {
      const participants = 'objectParticipant' in data
        ? (data as { objectParticipant?: { id: string; name: string; entity_type: string }[] }).objectParticipant ?? []
        : [];
      return (
        <ItemParticipants
          participants={participants}
          stixDomainObjectId={data.id}
        />
      );
    }
    case 'revoked': {
      const revoked = 'revoked' in data ? (data as { revoked?: boolean }).revoked ?? false : false;
      return (
        <ItemBoolean
          status={revoked}
          label={revoked ? t_i18n('Yes') : t_i18n('No')}
          reverse
        />
      );
    }

    case 'created':
    case 'modified':
    case 'created_at':
    case 'updated_at':
    case 'published':
    case 'first_seen':
    case 'last_seen':
    case 'start_time':
    case 'submitted':
    case 'analysis_started':
    case 'analysis_ended':
    case 'valid_from':
    case 'valid_until':
    case 'due_date':
    case 'stop_time': {
      const dateValue = (data as Record<string, unknown>)[attribute];
      if (!dateValue) {
        return (
          <Typography variant="body2" sx={{ color: 'text.disabled' }}>
            -
          </Typography>
        );
      }
      return <Typography variant="body2">{fldt(dateValue)}</Typography>;
    }

    case 'x_opencti_reliability': {
      const reliability = 'x_opencti_reliability' in data
        ? (data as { x_opencti_reliability?: string }).x_opencti_reliability
        : undefined;
      return (
        <ItemOpenVocab
          displayMode="chip"
          type="reliability_ov"
          value={reliability}
        />
      );
    }
    case 'killChainPhases': {
      const killChainPhases = (data as Record<string, unknown>).killChainPhases as
        | ReadonlyArray<{
          id: string;
          entity_type: string;
          kill_chain_name: string;
          phase_name: string;
          x_opencti_order?: number | null;
        }>
        | undefined;
      return (
        <FieldOrEmpty source={killChainPhases}>
          <List sx={{ py: 0 }}>
            {killChainPhases?.map((phase) => (
              <ListItem key={phase.id} dense divider>
                <ListItemText
                  primary={phase.phase_name}
                  secondary={phase.kill_chain_name}
                />
              </ListItem>
            ))}
          </List>
        </FieldOrEmpty>
      );
    }
    case 'x_opencti_main_observable_type': {
      const obsType = 'x_opencti_main_observable_type' in data
        ? (data as { x_opencti_main_observable_type?: string }).x_opencti_main_observable_type
        : undefined;
      return (
        <ItemOpenVocab
          displayMode="chip"
          type="observable_types_ov"
          value={obsType}
        />
      );
    }
    case 'x_opencti_workflow_id': {
      const status = 'status' in data
        ? (data as { status?: unknown; workflowEnabled?: boolean }).status ?? null
        : null;
      const workflowEnabled = 'workflowEnabled' in data
        ? (data as { workflowEnabled?: boolean }).workflowEnabled ?? false
        : false;
      return (
        <ItemStatus
          status={status as object}
          disabled={!workflowEnabled}
        />
      );
    }
    case 'pattern_type': {
      const patternType = 'pattern_type' in data
        ? (data as { pattern_type?: string }).pattern_type
        : undefined;
      if (!patternType) {
        return (
          <Typography variant="body2" sx={{ color: 'text.disabled' }}>
            -
          </Typography>
        );
      }
      return <ItemPatternType label={patternType} />;
    }
    case 'description':
    case 'x_opencti_description': {
      const desc = (data as Record<string, unknown>)[attribute];
      if (!desc) {
        return (
          <Typography variant="body2" sx={{ color: 'text.disabled' }}>
            -
          </Typography>
        );
      }
      return <ExpandableMarkdown source={desc as string} limit={400} />;
    }
    case 'height': {
      const heights = (data as Record<string, unknown>).height as
        | ReadonlyArray<{ measure?: number | null; date_seen?: string | null }>
        | null
        | undefined;
      return (
        <FieldOrEmpty source={heights}>
          <List sx={{ py: 0 }}>
            {heights?.map((h, i) => (
              <ListItem key={i} dense divider>
                <ListItemText
                  primary={h.measure != null ? `${h.measure} cm` : '-'}
                  secondary={h.date_seen ? fldt(h.date_seen) : t_i18n('Unknown date')}
                />
              </ListItem>
            ))}
          </List>
        </FieldOrEmpty>
      );
    }
    case 'weight': {
      const weights = (data as Record<string, unknown>).weight as
        | ReadonlyArray<{ measure?: number | null; date_seen?: string | null }>
        | null
        | undefined;
      return (
        <FieldOrEmpty source={weights}>
          <List sx={{ py: 0 }}>
            {weights?.map((w, i) => (
              <ListItem key={i} dense divider>
                <ListItemText
                  primary={w.measure != null ? `${w.measure} kg` : '-'}
                  secondary={w.date_seen ? fldt(w.date_seen) : t_i18n('Unknown date')}
                />
              </ListItem>
            ))}
          </List>
        </FieldOrEmpty>
      );
    }
    case 'date_of_birth': {
      const value = (data as Record<string, unknown>).date_of_birth as string | undefined;
      if (!value) {
        return <Typography variant="body2" sx={{ color: 'text.disabled' }}>-</Typography>;
      }
      return <Typography variant="body2">{fldt(value)}</Typography>;
    }
    case 'primary_motivation': {
      const value = (data as Record<string, unknown>).primary_motivation as string | undefined;
      return <ItemOpenVocab displayMode="chip" type="attack-motivation-ov" value={value} />;
    }
    case 'secondary_motivations': {
      const types = (data as Record<string, unknown>).secondary_motivations as string[] | undefined;
      return (
        <FieldOrEmpty source={types}>
          <Stack direction="row" flexWrap="wrap" gap={1}>
            {types?.map((type) => (
              <ItemOpenVocab key={type} displayMode="chip" type="attack-motivation-ov" value={type} />
            ))}
          </Stack>
        </FieldOrEmpty>
      );
    }
    // open vocabs
    case 'priority': {
      const priority = (data as Record<string, unknown>).priority as string | undefined;
      return <ItemOpenVocab displayMode="chip" type="case_priority_ov" value={priority} />;
    }
    case 'severity': {
      const severity = (data as Record<string, unknown>).severity as string | undefined;
      return <ItemOpenVocab displayMode="chip" type="case_severity_ov" value={severity} />;
    }
    case 'incident_type': {
      const incidentType = (data as Record<string, unknown>).incident_type as string | undefined;
      return <ItemOpenVocab displayMode="chip" type="incident_type_ov" value={incidentType} />;
    }
    case 'resource_level': {
      const resourceLevel = (data as Record<string, unknown>).resource_level as string | undefined;
      return <ItemOpenVocab displayMode="chip" type="attack-resource-level-ov" value={resourceLevel} />;
    }
    case 'x_opencti_organization_type': {
      const orgType = (data as Record<string, unknown>).x_opencti_organization_type as string | undefined;
      return <ItemOpenVocab displayMode="chip" type="organization_type_ov" value={orgType} />;
    }
    case 'eye_color': {
      const value = (data as Record<string, unknown>).eye_color as string | undefined;
      return <ItemOpenVocab displayMode="chip" type="eye-color-ov" value={value} />;
    }
    case 'hair_color': {
      const value = (data as Record<string, unknown>).hair_color as string | undefined;
      return <ItemOpenVocab displayMode="chip" type="hair-color-ov" value={value} />;
    }
    case 'threat_actor_types': {
      const types = (data as Record<string, unknown>).threat_actor_types as string[] | undefined;
      return (
        <FieldOrEmpty source={types}>
          <Stack direction="row" flexWrap="wrap" gap={1}>
            {types?.map((type) => (
              <ItemOpenVocab key={type} displayMode="chip" type="threat-actor-type-ov" value={type} />
            ))}
          </Stack>
        </FieldOrEmpty>
      );
    }
    case 'malware_types': {
      const types = (data as Record<string, unknown>).malware_types as string[] | undefined;
      return (
        <FieldOrEmpty source={types}>
          <Stack direction="row" flexWrap="wrap" gap={1}>
            {types?.map((type) => (
              <ItemOpenVocab key={type} displayMode="chip" type="malware-type-ov" value={type} />
            ))}
          </Stack>
        </FieldOrEmpty>
      );
    }
    case 'channel_types': {
      const types = (data as Record<string, unknown>).channel_types as string[] | undefined;
      return (
        <FieldOrEmpty source={types}>
          <Stack direction="row" flexWrap="wrap" gap={1}>
            {types?.map((type) => (
              <ItemOpenVocab key={type} displayMode="chip" type="channel_types_ov" value={type} />
            ))}
          </Stack>
        </FieldOrEmpty>
      );
    }
    case 'tool_types': {
      const types = (data as Record<string, unknown>).tool_types as string[] | undefined;
      return (
        <FieldOrEmpty source={types}>
          <Stack direction="row" flexWrap="wrap" gap={1}>
            {types?.map((type) => (
              <ItemOpenVocab key={type} displayMode="chip" type="tool-type-ov" value={type} />
            ))}
          </Stack>
        </FieldOrEmpty>
      );
    }
    case 'note_types': {
      const types = (data as Record<string, unknown>).note_types as string[] | undefined;
      return (
        <FieldOrEmpty source={types}>
          <Stack direction="row" flexWrap="wrap" gap={1}>
            {types?.map((type) => (
              <ItemOpenVocab key={type} displayMode="chip" type="note_types_ov" value={type} />
            ))}
          </Stack>
        </FieldOrEmpty>
      );
    }
    case 'response_types': {
      const types = (data as Record<string, unknown>).response_types as string[] | undefined;
      return (
        <FieldOrEmpty source={types}>
          <Stack direction="row" flexWrap="wrap" gap={1}>
            {types?.map((type) => (
              <ItemOpenVocab key={type} displayMode="chip" type="response_types_ov" value={type} />
            ))}
          </Stack>
        </FieldOrEmpty>
      );
    }
    case 'information_types': {
      const types = (data as Record<string, unknown>).information_types as string[] | undefined;
      return (
        <FieldOrEmpty source={types}>
          <Stack direction="row" flexWrap="wrap" gap={1}>
            {types?.map((type) => (
              <ItemOpenVocab key={type} displayMode="chip" type="information_types_ov" value={type} />
            ))}
          </Stack>
        </FieldOrEmpty>
      );
    }
    case 'takedown_types': {
      const types = (data as Record<string, unknown>).takedown_types as string[] | undefined;
      return (
        <FieldOrEmpty source={types}>
          <Stack direction="row" flexWrap="wrap" gap={1}>
            {types?.map((type) => (
              <ItemOpenVocab key={type} displayMode="chip" type="takedown_types_ov" value={type} />
            ))}
          </Stack>
        </FieldOrEmpty>
      );
    }
    case 'event_types': {
      const types = (data as Record<string, unknown>).event_types as string[] | undefined;
      return (
        <FieldOrEmpty source={types}>
          <Stack direction="row" flexWrap="wrap" gap={1}>
            {types?.map((type) => (
              <ItemOpenVocab key={type} displayMode="chip" type="event_types_ov" value={type} />
            ))}
          </Stack>
        </FieldOrEmpty>
      );
    }

    default: {
      const value = (data as Record<string, unknown>)[attribute];

      if (value === undefined || value === null || value === '') {
        return (
          <Typography variant="body2" sx={{ color: 'text.disabled' }}>
            -
          </Typography>
        );
      }

      if (Array.isArray(value)) {
        if (value.length === 0) {
          return (
            <Typography variant="body2" sx={{ color: 'text.disabled' }}>
              -
            </Typography>
          );
        }
        if (typeof value[0] === 'object') {
          return (
            <Stack direction="row" flexWrap="wrap" gap={1}>
              {(value as { name?: string; value?: string }[]).map((item, i) => (
                <Tag key={i} label={item.name ?? item.value ?? String(item)} />
              ))}
            </Stack>
          );
        }
        return (
          <FieldOrEmpty source={value}>
            <Stack direction="row" flexWrap="wrap" gap={1}>
              {(value as string[]).map((item) => (
                <Tag key={item} label={item} />
              ))}
            </Stack>
          </FieldOrEmpty>
        );
      }

      return (
        <Typography variant="body2" sx={{ wordBreak: 'break-word' }}>
          {String(value)}
        </Typography>
      );
    }
  }
};

const WidgetCustomAttributesCard: FunctionComponent<WidgetCustomAttributesCardProps> = ({
  column,
  data,
}) => {
  const theme = useTheme<Theme>();
  const { t_i18n, fldt } = useFormatter();
  const label = column.label ?? column.attribute ?? '';

  return (
    <Box sx={{ marginBottom: theme.spacing(2), paddingTop: theme.spacing(2) }}>
      <Typography variant="h4" sx={{ marginBottom: theme.spacing(0.5) }}>
        {t_i18n(label)}
      </Typography>
      {renderAttributeValue(column.attribute ?? '', data, t_i18n, fldt)}
    </Box>
  );
};

export default WidgetCustomAttributesCard;
