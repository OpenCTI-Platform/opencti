import React, { FunctionComponent, ReactNode, useId, useState } from 'react';
import { CheckCircleOutlined, ExpandLessOutlined, ExpandMoreOutlined } from '@mui/icons-material';
import { Text } from '@filigran/design-system';
import { useTheme } from '@mui/material/styles';
import IconButton from '@common/button/IconButton';
import { useFormatter } from '../../../../../components/i18n';
import type { Theme } from '../../../../../components/Theme';
import ConfigPresetResultLine from './ConfigPresetResultLine';

export interface ConfigPresetResultItem {
  readonly type: string;
  readonly key: string;
  readonly status: string;
  readonly reason?: string | null;
  // The name of the item, and whether the UI translates it
  readonly label: string;
  readonly translatable: boolean;
  // The type of the item and its place among the types, the group of the type
  readonly type_label: string;
  readonly type_index: number;
  readonly group: { readonly key: string; readonly label: string };
}

interface ResultType {
  readonly key: string;
  readonly label: string;
  readonly index: number;
  readonly group: ConfigPresetResultItem['group'];
  readonly items: ConfigPresetResultItem[];
}

interface ResultGroup {
  readonly key: string;
  readonly label: string;
  readonly types: ResultType[];
}

const isFailed = (item: ConfigPresetResultItem) => item.status === 'FAILED';
const isImported = (item: ConfigPresetResultItem) => item.status === 'CREATED' || item.status === 'OVERWRITTEN';
// A group or a type is done when something was imported in it and nothing failed
const isDone = (items: ReadonlyArray<ConfigPresetResultItem>) => items.some(isImported) && !items.some(isFailed);

// The results by type, in the order of the types, then the types by group, in the order of the first of their types
const groupResults = (results: ReadonlyArray<ConfigPresetResultItem>): ResultGroup[] => {
  const types = new Map<string, ResultType>();
  results.forEach((item) => {
    const type = types.get(item.type) ?? { key: item.type, label: item.type_label, index: item.type_index, group: item.group, items: [] };
    type.items.push(item);
    types.set(item.type, type);
  });
  const groups = new Map<string, ResultGroup>();
  [...types.values()].sort((a, b) => a.index - b.index).forEach((type) => {
    const group = groups.get(type.group.key) ?? { key: type.group.key, label: type.group.label, types: [] };
    group.types.push(type);
    groups.set(type.group.key, group);
  });
  return [...groups.values()];
};

// The items that did not fail, out of all of them: what the header of a group or of a type counts
const countImported = (items: ReadonlyArray<ConfigPresetResultItem>) => `${items.filter((item) => !isFailed(item)).length}/${items.length}`;

interface ResultSectionProps {
  label: string;
  // Open from the start: something in the section failed. The chevron then closes it, and opens a section that starts closed.
  startsOpen: boolean;
  // Everything in it went well: a tick leads the label
  isDone: boolean;
  nested?: boolean;
  children: ReactNode;
}

const ResultSection: FunctionComponent<ResultSectionProps> = ({ label, startsOpen, isDone: done, nested = false, children }) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  const [toggled, setToggled] = useState(false);
  const isOpen = toggled !== startsOpen;
  const contentId = useId();
  return (
    <div>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: theme.spacing(1, 0) }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: theme.spacing(1) }}>
          {done && <CheckCircleOutlined aria-hidden data-testid="config-preset-result-tick" fontSize="small" style={{ color: theme.palette.success.main }} />}
          <Text variant={nested ? 'content-base' : 'title-sm'}>{label}</Text>
        </div>
        <IconButton
          aria-label={`${isOpen ? t_i18n('Collapse') : t_i18n('Expand')} ${label}`}
          aria-expanded={isOpen}
          aria-controls={contentId}
          onClick={() => setToggled((current) => !current)}
        >
          {isOpen ? <ExpandLessOutlined /> : <ExpandMoreOutlined />}
        </IconButton>
      </div>
      {isOpen && (
        <div id={contentId} style={{ display: 'flex', flexDirection: 'column', gap: theme.spacing(1.5), padding: theme.spacing(0, 0, 2, 3.5) }}>
          {children}
        </div>
      )}
    </div>
  );
};

// The name of an item of a result: translated when it is a label of the UI, as it is when it is the name of what was imported
export const useResultLabel = () => {
  const { t_i18n } = useFormatter();
  return (item: Pick<ConfigPresetResultItem, 'label' | 'translatable'>) => (item.translatable ? t_i18n(item.label) : item.label);
};

interface ConfigPresetResultGroupsProps {
  results: ReadonlyArray<ConfigPresetResultItem>;
}

// The results of an import grouped like the selection (groups, then types, then items). What went well stays closed, whatever failed is open.
const ConfigPresetResultGroups: FunctionComponent<ConfigPresetResultGroupsProps> = ({ results }) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  const resultLabel = useResultLabel();
  return (
    <div>
      {groupResults(results).map((group) => {
        const groupItems = group.types.flatMap((type) => type.items);
        return (
          <div key={group.key} style={{ borderBottom: `1px solid ${theme.palette.divider}` }}>
            <ResultSection label={`${t_i18n(group.label)} (${countImported(groupItems)})`} startsOpen={groupItems.some(isFailed)} isDone={isDone(groupItems)}>
              {group.types.map((type) => (
                <ResultSection
                  key={type.key}
                  label={`${t_i18n(type.label)} (${countImported(type.items)})`}
                  startsOpen={type.items.some(isFailed)}
                  isDone={isDone(type.items)}
                  nested
                >
                  {type.items.map((item) => (
                    <ConfigPresetResultLine key={item.key} label={resultLabel(item)} status={item.status} reason={item.reason} isDone={isImported(item)} />
                  ))}
                </ResultSection>
              ))}
            </ResultSection>
          </div>
        );
      })}
    </div>
  );
};

export default ConfigPresetResultGroups;
