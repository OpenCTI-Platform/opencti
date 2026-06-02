import React, { FunctionComponent } from 'react';
import { Box, Stack, Typography } from '@mui/material';
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
import ItemCopy from '../../../components/ItemCopy';
import ItemAssignees from '../../../components/ItemAssignees';
import ItemParticipants from '../../../components/ItemParticipants';
import ExpandableMarkdown from '../../../components/ExpandableMarkdown';
import FieldOrEmpty from '../../../components/FieldOrEmpty';
import Tag from '@common/tag/Tag';
import { StixCoreObjectsCustomAttributesQuery$data } from '@components/common/stix_core_objects/__generated__/StixCoreObjectsCustomAttributesQuery.graphql';

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

    case 'standard_id': {
      if (!data.standard_id) {
        return (
          <Typography variant="body2" sx={{ color: 'text.disabled' }}>
            -
          </Typography>
        );
      }
      return (
        <Typography
          sx={{
            padding: '5px 5px 5px 10px',
            fontFamily: 'Consolas, monaco, monospace',
            fontSize: 11,
            backgroundColor: 'rgba(255, 255, 255, 0.02)',
            lineHeight: '18px',
          }}
        >
          <ItemCopy content={data.standard_id} />
        </Typography>
      );
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
