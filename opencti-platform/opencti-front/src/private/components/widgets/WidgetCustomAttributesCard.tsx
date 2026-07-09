import React, { FunctionComponent } from 'react';
import { Box, List, ListItem, Stack, Typography } from '@mui/material';
import { useTheme } from '@mui/styles';
import type { Theme } from 'src/components/Theme';
import { useFormatter } from 'src/components/i18n';
import type { WidgetColumn, WidgetHost } from 'src/utils/widget/widget';
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
import { EMPTY_VALUE } from 'src/utils/String';

export type StixCoreObject = NonNullable<StixCoreObjectsCustomAttributesQuery$data['stixCoreObject']>;

interface WidgetCustomAttributesCardProps {
  column: WidgetColumn;
  data: StixCoreObject | null | undefined;
  isCustomViewReadOnly?: boolean;
  host?: WidgetHost;
}

const isString = (v: unknown): v is string => typeof v === 'string';
const isNumber = (v: unknown): v is number => typeof v === 'number' && !Number.isNaN(v);
const isBoolean = (v: unknown): v is boolean => typeof v === 'boolean';
const isStringArray = (v: unknown): v is string[] =>
  Array.isArray(v) && v.every(isString);
const isObjectArray = (v: unknown): v is Record<string, unknown>[] =>
  Array.isArray(v) && v.every((item) => typeof item === 'object' && item !== null);

const getField = <T,>(
  data: unknown,
  key: string,
  guard?: (v: unknown) => v is T,
): T | undefined => {
  const value = (data as Record<string, unknown>)[key];
  if (guard) return guard(value) ? value : undefined;
  return value as T | undefined;
};

const empty = () => (
  <Typography>
    {EMPTY_VALUE}
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

  switch (attributeType) {
    case 'date': {
      const value = getField(data, attribute, isString);
      return (
        <FieldOrEmpty source={value}>
          <Typography variant="body2">{fldt(value)}</Typography>
        </FieldOrEmpty>
      );
    }

    case 'boolean': {
      const bool = getField(data, attribute, isBoolean);
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
      const value = getField(data, attribute, isString);
      return (
        <FieldOrEmpty source={value}>
          <Tag label={value} />
        </FieldOrEmpty>
      );
    }

    case 'tag_list': {
      const list = getField(data, attribute, isStringArray);
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
      const list = getField(data, attribute, isStringArray);
      return (
        <FieldOrEmpty source={list}>
          <TextList list={list} />
        </FieldOrEmpty>
      );
    }

    case 'markdown': {
      const value = getField(data, attribute, isString);
      if (!value) return empty();
      return <ExpandableMarkdown source={value} limit={400} />;
    }

    case 'score': {
      const score = getField(data, attribute, isNumber);
      return <ItemScore score={score ?? null} />;
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
      const list = getField(data, attribute, isStringArray);
      if (list) {
        return (
          <FieldOrEmpty source={list}>
            {list.map((v) => <ValueCopy key={v} value={v} />)}
          </FieldOrEmpty>
        );
      }
      const value = getField(data, attribute, isString);
      if (!value) return empty();
      return <ValueCopy value={value} />;
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
  host?: WidgetHost,
) => {
  const { attribute } = column;
  if (!attribute) return null;

  if (!data) {
    return (
      <Typography>
        {EMPTY_VALUE}
      </Typography>
    );
  }

  const entityType = data.entity_type ?? '';
  const isSCO = 'observable_value' in data;
  const specificRenderer
    = entityTypeRenderers[entityType]?.[attribute]
      ?? (isSCO ? entityTypeRenderers['Stix-Cyber-Observable']?.[attribute] : undefined);

  if (specificRenderer) {
    return specificRenderer(data, t_i18n, fldt, host);
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
      const labels = getField<{ id: string; value: string; color: string }[]>(data, 'objectLabel');
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
      const workflowEnabled = getField(data, 'workflowEnabled', isBoolean) ?? false;
      return <ItemStatus status={status as object} disabled={!workflowEnabled} />;
    }

    default: {
      const value = getField(data, attribute);
      if (value === undefined || value === null || value === '') return empty();

      const objectArr = getField(data, attribute, isObjectArray);
      if (objectArr) {
        if (objectArr.length === 0) return empty();
        return (
          <Stack direction="row" flexWrap="wrap" gap={1}>
            {objectArr.map((item, i) => (
              <Tag key={i} label={String(item.name ?? item.value ?? item)} />
            ))}
          </Stack>
        );
      }

      const stringArr = getField(data, attribute, isStringArray);
      if (stringArr) {
        if (stringArr.length === 0) return empty();
        return (
          <FieldOrEmpty source={stringArr}>
            <Stack direction="row" flexWrap="wrap" gap={1}>
              {stringArr.map((item) => <Tag key={item} label={item} />)}
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
  host,
}) => {
  const theme = useTheme<Theme>();
  const { t_i18n, fldt } = useFormatter();
  const label = column.label ?? column.attribute ?? '';

  return (
    <Box sx={{ marginBottom: theme.spacing(2), paddingTop: theme.spacing(2) }}>
      <Typography variant="h4" sx={{ marginBottom: theme.spacing(0.5) }}>
        {t_i18n(label)}
      </Typography>
      {renderAttributeValue(column, data, t_i18n, fldt, host)}
    </Box>
  );
};

export default WidgetCustomAttributesCard;
