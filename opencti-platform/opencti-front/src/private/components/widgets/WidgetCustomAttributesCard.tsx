import React, { FunctionComponent } from 'react';
import { Box, List, ListItem, Stack, Typography } from '@mui/material';
import { useTheme } from '@mui/styles';
import type { Theme } from 'src/components/Theme';
import { useFormatter } from 'src/components/i18n';
import type { WidgetColumn } from 'src/utils/widget/widget';
import ItemMarkings from '../../../components/ItemMarkings';
import ItemAuthor from '../../../components/ItemAuthor';
import ItemConfidence from '../../../components/ItemConfidence';
import ItemBoolean from '../../../components/ItemBoolean';
import ItemCreators from '../../../components/ItemCreators';
import ItemStatus from '../../../components/ItemStatus';
import ItemAssignees from '../../../components/ItemAssignees';
import ItemParticipants from '../../../components/ItemParticipants';
import ExpandableMarkdown from '../../../components/ExpandableMarkdown';
import FieldOrEmpty from '../../../components/FieldOrEmpty';
import Tag from '@common/tag/Tag';
import TextList from '@common/text/TextList';
import ItemScore from '../../../components/ItemScore';
import ItemCopy from '../../../components/ItemCopy';
import { StixCoreObjectsCustomAttributesQuery$data } from '@components/common/stix_core_objects/__generated__/StixCoreObjectsCustomAttributesQuery.graphql';
import { entityTypeRenderers } from 'src/utils/widget/widgetCustomAttributesRendererUtils';
import ListItemText from '@mui/material/ListItemText';
import { openVocabListRenderers, openVocabSingleRenderers } from 'src/utils/widget/widgetOpenVocabRendererUtils';

export type StixCoreObject = NonNullable<StixCoreObjectsCustomAttributesQuery$data['stixCoreObject']>;

interface WidgetCustomAttributesCardProps {
  column: WidgetColumn;
  data: StixCoreObject | null | undefined;
  isCustomViewReadOnly?: boolean;
}

const getField = <T,>(data: unknown, key: string): T | undefined =>
  (data as Record<string, unknown>)[key] as T | undefined;

const empty = (italic = false) => (
  <Typography variant="body2" sx={{ color: 'text.disabled', ...(italic && { fontStyle: 'italic' }) }}>
    -
  </Typography>
);

const ValueCopy = ({ value }: { value: string }) => (
  <pre><ItemCopy content={value} /></pre>
);

const renderByAttributeType = (
  column: WidgetColumn,
  data: StixCoreObject,
  t_i18n: (s: string) => string,
  fldt: (s: unknown) => string,
) => {
  const { attribute, attributeType } = column;
  if (!attribute || !attributeType) return null;

  const value = getField(data, attribute);

  switch (attributeType) {
    case 'date': {
      if (!value) return empty();
      return <Typography variant="body2">{fldt(value)}</Typography>;
    }
    case 'boolean': {
      const bool = value as boolean | undefined;
      if (bool === undefined || bool === null) return empty();
      return (
        <ItemBoolean
          status={bool}
          label={bool ? t_i18n('Yes') : t_i18n('No')}
          reverse
        />
      );
    }
    case 'tag': {
      if (!value) return empty();
      return <Tag label={String(value)} />;
    }
    case 'tag_list': {
      const list = value as string[] | undefined;
      if (!list?.length) return empty();
      return (
        <FieldOrEmpty source={list}>
          <Stack direction="row" flexWrap="wrap" gap={1}>
            {list.map((item) => <Tag key={item} label={item} />)}
          </Stack>
        </FieldOrEmpty>
      );
    }
    case 'text_list': {
      return <TextList list={value as string[] | undefined} />;
    }
    case 'markdown': {
      if (!value) return empty();
      return <ExpandableMarkdown source={value as string} limit={400} />;
    }
    case 'score': {
      return <ItemScore score={value as number ?? null} />;
    }
    case 'open_vocab': {
      return openVocabSingleRenderers[attribute]?.(data as Record<string, unknown>)
        ?? empty();
    }
    case 'open_vocab_list': {
      return openVocabListRenderers[attribute]?.(data as Record<string, unknown>)
        ?? empty();
    }
    case 'copy': {
      const list = Array.isArray(value) ? value as string[] : undefined;
      if (list) {
        return (
          <FieldOrEmpty source={list}>
            {list.map((v) => <ValueCopy key={v} value={v} />)}
          </FieldOrEmpty>
        );
      }
      if (!value) return empty();
      return <ValueCopy value={value as string} />;
    }
    case 'cvss_score':
      return null;
    default:
      return null;
  }
};

const renderAttributeValue = (
  column: WidgetColumn,
  data: StixCoreObject | null | undefined,
  t_i18n: (s: string) => string,
  fldt: (s: unknown) => string,
) => {
  const { attribute } = column;
  if (!attribute) return null;
  const entityType = data?.entity_type ?? '';
  if (!data) {
    return (
      <Typography variant="body2" sx={{ color: 'text.disabled', fontStyle: 'italic' }}>
        —
      </Typography>
    );
  }

  const isSCO = 'observable_value' in data;
  const specificRenderer
    = entityTypeRenderers[entityType]?.[attribute]
      ?? (isSCO ? entityTypeRenderers['Stix-Cyber-Observable']?.[attribute] : undefined);
  if (specificRenderer) {
    return specificRenderer(data, t_i18n, fldt);
  }

  const byType = renderByAttributeType(column, data, t_i18n, fldt);
  if (byType !== null) return byType;

  switch (attribute) {
    case 'objectMarking':
      return <ItemMarkings markingDefinitions={data.objectMarking ?? []} />;

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
      const labels = data.objectLabel as { id: string; value: string; color: string }[] | undefined;
      return (
        <FieldOrEmpty source={labels}>
          <Stack direction="row" flexWrap="wrap" gap={1}>
            {labels?.map((label) => (
              <Tag key={label.id} label={label.value} color={label.color} />
            ))}
          </Stack>
        </FieldOrEmpty>
      );
    }

    case 'creators':
      return <ItemCreators creators={data.creators ?? []} />;

    case 'objectAssignee': {
      const assignees = getField<{ id: string; name: string; entity_type: string }[]>(data, 'objectAssignee') ?? [];
      return <ItemAssignees assignees={assignees} stixDomainObjectId={data.id} readOnly />;
    }

    case 'objectParticipant': {
      const participants = getField<{ id: string; name: string; entity_type: string }[]>(data, 'objectParticipant') ?? [];
      return <ItemParticipants participants={participants} stixDomainObjectId={data.id} readOnly />;
    }

    case 'killChainPhases': {
      const phases = getField<ReadonlyArray<{
        id: string;
        kill_chain_name: string;
        phase_name: string;
      }>>(data, 'killChainPhases');
      return (
        <FieldOrEmpty source={phases}>
          <List sx={{ py: 0 }}>
            {phases?.map((phase) => (
              <ListItem key={phase.id} dense divider>
                <ListItemText primary={phase.phase_name} secondary={phase.kill_chain_name} />
              </ListItem>
            ))}
          </List>
        </FieldOrEmpty>
      );
    }

    case 'x_opencti_workflow_id': {
      const status = getField<unknown>(data, 'status') ?? null;
      const workflowEnabled = getField<boolean>(data, 'workflowEnabled') ?? false;
      return <ItemStatus status={status as object} disabled={!workflowEnabled} />;
    }

    default: {
      const value = getField(data, attribute);
      if (value === undefined || value === null || value === '') return empty();
      if (Array.isArray(value)) {
        if (value.length === 0) return empty();
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
              {(value as string[]).map((item) => <Tag key={item} label={item} />)}
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
      {renderAttributeValue(column, data, t_i18n, fldt)}
    </Box>
  );
};

export default WidgetCustomAttributesCard;
