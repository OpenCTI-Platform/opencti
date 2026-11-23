import React, { useState } from 'react';
import { Button as FdsButton, Chip, Icon, Text } from '@filigran/design-system';
import Box from '@mui/material/Box';
import Button from '@common/button/Button';
import { useFormatter } from '../../../../components/i18n';
import { IR_PIR_TYPES, rulesForGroup, rulesForType, type IrPirType } from './irPresetRules';
import { defaultItemName, emptyValue, validatePresetItems, type IrPresetItem, type IrPresetValue, type IrRuleInstance } from './irPresetDraft';
import { newId } from './irConfigTypes';
import { IrAddRuleMenu, IrJoinDivider, IrPresetItemCard } from './IrPresetItemCard';

interface IrRulesStepProps {
  pirType: IrPirType;
  flags: string[];
  items: IrPresetItem[];
  onChange: (items: IrPresetItem[]) => void;
  // ids of the items the user renamed: the others follow their default name as values change
  renamed?: Set<string>;
  onRenamedChange?: (renamed: Set<string>) => void;
  showErrors?: boolean; // after the user tried to go to the next step
}

const newRule = (ruleKey: string): IrRuleInstance => ({ id: newId('r'), ruleKey, value: emptyValue() });

// Step 2 of the creation wizard: the rules (OR) and groups of rules (AND) that flag entities
const IrRulesStep = ({ pirType, flags, items, onChange, renamed = new Set(), onRenamedChange, showErrors = false }: IrRulesStepProps) => {
  const { t_i18n } = useFormatter();
  const [groupMenuFor, setGroupMenuFor] = useState<string | null>(null);
  const type = IR_PIR_TYPES.find((p) => p.key === pirType);
  const typeLabel = t_i18n(type?.label ?? pirType);
  const flagLabels = flags.map((f) => t_i18n(`entity_${f}`));
  const menuHeading = t_i18n('{type} rules', { values: { type: typeLabel } });
  const errors = showErrors ? validatePresetItems(items) : [];

  // Every change goes through here: the items the user did not rename take their default name
  const commit = (next: IrPresetItem[], nextRenamed: Set<string> = renamed) => onChange(
    next.map((item) => (nextRenamed.has(item.id) ? item : { ...item, name: defaultItemName(pirType, item, t_i18n) })),
  );
  const update = (id: string, change: (item: IrPresetItem) => IrPresetItem | null) => commit(
    items.flatMap((item) => {
      if (item.id !== id) return [item];
      const next = change(item);
      return next ? [next] : [];
    }),
  );
  const setRuleValue = (item: IrPresetItem, ruleId: string, value: IrPresetValue): IrPresetItem => {
    if (item.kind === 'rule') return { ...item, rule: { ...item.rule, value } };
    if (item.kind === 'group') return { ...item, rules: item.rules.map((r) => (r.id === ruleId ? { ...r, value } : r)) };
    return item;
  };
  const rename = (id: string, name: string) => {
    const next = new Set(renamed);
    // an emptied name goes back to the default one
    if (name.trim()) next.add(id);
    else next.delete(id);
    onRenamedChange?.(next);
    commit(items.map((item) => (item.id === id ? { ...item, name: name.trim() } : item)), next);
  };
  const addRule = (ruleKey: string) => commit([...items, { id: newId('i'), kind: 'rule', name: '', rule: newRule(ruleKey) }]);
  const addCustom = () => commit([...items, { id: newId('i'), kind: 'custom', name: '', filters: null }]);
  const addGroup = () => {
    const id = newId('i');
    commit([...items, { id, kind: 'group', name: '', rules: [] }]);
    setGroupMenuFor(id);
  };

  return (
    <Box sx={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
      <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, bgcolor: 'action.hover', borderRadius: 1, px: 2, py: 1.5 }}>
        <Text as="span" variant="content-caption">
          <Box component="span" sx={{ color: 'text.secondary' }}>{t_i18n('PIR type')}</Box>
        </Text>
        <Text as="span" variant="content-compact-bold">{typeLabel}</Text>
        <Box sx={{ flex: 1 }} />
        <Text as="span" variant="content-caption">
          <Box component="span" sx={{ color: 'text.secondary' }}>{t_i18n('Chosen in step 1, General settings')}</Box>
        </Text>
      </Box>

      <Box>
        <Text as="div" variant="title-sm" style={{ marginBottom: 4 }}>{t_i18n('What this PIR flags')}</Text>
        <Text as="p" variant="content-caption" style={{ marginBottom: 12 }}>
          <Box component="span" sx={{ color: 'text.secondary' }}>
            {t_i18n('{type} PIRs flag {flags}. Each rule below describes which {subject} to flag.', {
              values: { type: typeLabel, flags: flagLabels.join(', '), subject: t_i18n(type?.subject ?? 'Entities').toLowerCase() },
            })}
          </Box>
        </Text>
        <Box sx={{ display: 'flex', alignItems: 'center', flexWrap: 'wrap', gap: 1 }}>
          <Text as="span" variant="content-compact">{t_i18n('Flag')}</Text>
          {flagLabels.map((label) => <Chip key={label} label={label} startIcon={<Icon name="lock" size={16} />} />)}
        </Box>
      </Box>

      <Box>
        <Text as="div" variant="title-sm" style={{ marginBottom: 4 }}>{t_i18n('Rules')}</Text>
        <Text as="p" variant="content-caption" style={{ marginBottom: 12 }}>
          <Box component="span" sx={{ color: 'text.secondary' }}>
            {t_i18n('Entities are flagged when they match any rule or group: rules are joined with OR. To require several rules at once, put them in a group: rules in a group are joined with AND.')}
          </Box>
        </Text>
        {errors.filter((e) => e.itemId === '').map((e) => (
          <Text key={e.message} as="p" variant="content-caption" style={{ marginBottom: 12 }}>
            <Box component="span" sx={{ color: 'error.main' }}>{t_i18n(e.message)}</Box>
          </Text>
        ))}
        {items.map((item, index) => (
          <React.Fragment key={item.id}>
            {index > 0 && <IrJoinDivider label={t_i18n('or')} />}
            <IrPresetItemCard
              item={item}
              flags={flags}
              groupRules={rulesForGroup(pirType, flags)}
              menuHeading={menuHeading}
              errors={errors.filter((e) => e.itemId === item.id)}
              groupMenuOpen={groupMenuFor === item.id}
              onGroupMenuOpenChange={(open) => setGroupMenuFor(open ? item.id : null)}
              onRename={(name) => rename(item.id, name)}
              onRemove={() => update(item.id, () => null)}
              onRuleValue={(ruleId, value) => update(item.id, (current) => setRuleValue(current, ruleId, value))}
              // a group whose last rule is removed goes too
              onRemoveGroupRule={(ruleId) => update(item.id, (current) => {
                if (current.kind !== 'group') return current;
                const rules = current.rules.filter((r) => r.id !== ruleId);
                return rules.length > 0 ? { ...current, rules } : null;
              })}
              onAddGroupRule={(ruleKey) => update(item.id, (current) => (current.kind === 'group' ? { ...current, rules: [...current.rules, newRule(ruleKey)] } : current))}
              onFilters={(filters) => update(item.id, (current) => (current.kind === 'custom' ? { ...current, filters } : current))}
            />
          </React.Fragment>
        ))}
        <Box sx={{ display: 'flex', gap: 1, mt: 2 }}>
          <IrAddRuleMenu
            heading={menuHeading}
            rules={rulesForType(pirType, flags)}
            onPick={addRule}
            onAdvanced={addCustom}
            trigger={<FdsButton type="button" priority="secondary" size="sm" startIcon={<Icon name="plus" size={16} />}>{t_i18n('Add rule')}</FdsButton>}
          />
          <Button variant="tertiary" size="small" startIcon={<Icon name="plus" size={16} />} onClick={addGroup}>{t_i18n('Add group')}</Button>
        </Box>
      </Box>
    </Box>
  );
};

export default IrRulesStep;
