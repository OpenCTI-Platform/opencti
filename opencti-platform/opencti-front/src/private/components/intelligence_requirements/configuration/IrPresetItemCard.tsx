import React, { ReactNode, Suspense, useEffect, useRef, useState } from 'react';
import { Button as FdsButton, Icon, Input, Menu, MenuContent, MenuGroup, MenuItem, MenuLabel, MenuSeparator, MenuTrigger, Separator, Spinner, Text } from '@filigran/design-system';
import Box from '@mui/material/Box';
import { alpha } from '@mui/material/styles';
import Button from '@common/button/Button';
import IconButton from '@common/button/IconButton';
import { useFormatter } from '../../../../components/i18n';
import IrPresetValueField from './IrPresetValueField';
import IrFilterBuilder from './IrFilterBuilder';
import { ADVANCED_RULE_KEY, getRule, type IrPresetRule } from './irPresetRules';
import { presetQueryChips, type IrPresetItem, type IrQueryChip, type IrPresetValue, type IrRuleInstance } from './irPresetDraft';

// The cards of the criteria step: one rule, a group of rules (AND) or advanced search criteria.

export interface IrItemError {
  itemId: string;
  ruleId?: string;
  message: string;
}

type Translate = (text: string) => string;

/**
 * The English texts of the preset draft (validation messages, words of the default names), as literal
 * keys so that the extraction keeps them in the catalogs. Any other text is translated as it is.
 */
export const presetText = (text: string, t_i18n: Translate): string => {
  switch (text) {
    case 'Add a value': return t_i18n('Add a value');
    case 'Add filters': return t_i18n('Add filters');
    case 'Add at least one rule': return t_i18n('Add at least one rule');
    case 'matching custom filters': return t_i18n('matching custom filters');
    case 'any': return t_i18n('any');
    case 'more rules': return t_i18n('more rules');
    case 'matching filters': return t_i18n('matching filters');
    case 'Target filters': return t_i18n('Target filters');
    case 'Source filters': return t_i18n('Source filters');
    default: return t_i18n(text);
  }
};

const ErrorText = ({ children }: { children: ReactNode }) => (
  <Text as="p" variant="content-caption" style={{ marginTop: 4 }}>
    <Box component="span" sx={{ color: 'error.main' }}>{children}</Box>
  </Text>
);

// A thin rule with a word in its middle: "or" between items, "AND" between the rules of a group
export const IrJoinDivider = ({ label, primary = false }: { label: string; primary?: boolean }) => (
  <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, my: 1 }}>
    <Box sx={{ flex: 1 }}><Separator /></Box>
    <Text as="span" variant="content-caption">
      <Box component="span" sx={{ color: primary ? 'primary.main' : 'text.secondary', fontWeight: primary ? 600 : undefined }}>{label}</Box>
    </Text>
    <Box sx={{ flex: 1 }}><Separator /></Box>
  </Box>
);

// The flagged entity is the source of the relationship (incoming) or its target (outgoing)
const flaggedSide = (rule: IrPresetRule): 'source' | 'target' | null => {
  const { build } = rule;
  switch (build.kind) {
    case 'linked':
    case 'linkedViaFilter':
      return build.direction === 'incoming' ? 'source' : 'target';
    case 'container':
    case 'containerFixed':
    case 'indicated':
      return 'target';
    default:
      return null;
  }
};

// The query of one rule as chips joined by AND
const QueryChips = ({ chips }: { chips: IrQueryChip[] }) => {
  const { t_i18n } = useFormatter();
  return (
    <Box sx={{ display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: 0.75 }}>
      {chips.map((chip, index) => (
        <React.Fragment key={`${chip.key}-${index}`}>
          {index > 0 && <Text as="span" variant="content-caption">{t_i18n('AND')}</Text>}
          {/* a read-only chip: the FDS Chip takes a plain label, and the value the user gave is coloured on its own */}
          <Box component="span" sx={{ display: 'inline-block', bgcolor: 'action.selected', borderRadius: 0.5, px: 0.75, py: 0.25 }}>
            <Text as="span" variant="content-caption">
              {`${chip.key} ${chip.operator ?? '='} `}
              <Box component="span" sx={chip.fromUser ? { color: 'primary.main', fontWeight: 600 } : undefined}>
                {chip.filterCount !== undefined ? t_i18n('{count, plural, one {# filter} other {# filters}}', { values: { count: chip.filterCount } }) : chip.values || '…'}
              </Box>
            </Text>
          </Box>
        </React.Fragment>
      ))}
    </Box>
  );
};

// The query of a rule, or of a group: the query of each of its rules, all of which must match
const RulesQuery = ({ title, rules, flags }: { title: string; rules: IrRuleInstance[]; flags: string[] }) => {
  const { t_i18n } = useFormatter();
  const queries = rules.map((rule) => presetQueryChips(rule, flags, (text) => presetText(text, t_i18n)));
  const sides = new Set(rules.map((rule) => flaggedSide(getRule(rule.ruleKey))));
  return (
    <Box sx={{ display: 'flex', flexDirection: 'column', gap: 0.5, maxWidth: 420 }}>
      <Text as="div" variant="content-compact-bold">{title}</Text>
      {queries.map((chips, index) => (
        <React.Fragment key={rules[index].id}>
          {index > 0 && (
            <Text as="div" variant="content-caption">
              <Box component="span" sx={{ fontWeight: 600 }}>{t_i18n('AND')}</Box>
            </Text>
          )}
          <QueryChips chips={chips} />
        </React.Fragment>
      ))}
      {queries.some((chips) => chips.some((chip) => chip.fromUser)) && <Text as="div" variant="content-caption">{t_i18n('Blue is your value.')}</Text>}
      {sides.has('source') && <Text as="div" variant="content-caption">{t_i18n('Flags the source of each matching relationship.')}</Text>}
      {sides.has('target') && <Text as="div" variant="content-caption">{t_i18n('Flags the target of each matching relationship.')}</Text>}
    </Box>
  );
};

export const QueryTooltip = ({ rule, flags }: { rule: IrRuleInstance; flags: string[] }) => {
  const { t_i18n } = useFormatter();
  return <RulesQuery title={t_i18n('Query this rule runs')} rules={[rule]} flags={flags} />;
};

// One tooltip for a whole group, on its header: the rules inside it have none of their own
export const GroupQueryButton = ({ rules, flags }: { rules: IrRuleInstance[]; flags: string[] }) => {
  const { t_i18n } = useFormatter();
  if (rules.length === 0) return null;
  return (
    <IconButton aria-label={t_i18n('Query this group runs')} tooltip={<RulesQuery title={t_i18n('Query this group runs')} rules={rules} flags={flags} />}>
      <Icon name="info" size={16} />
    </IconButton>
  );
};

// One rule: its fixed sentence, the value to fill, the query it runs and, inside a group, its own remove button
const IrRuleRow = ({ rule, flags, onChange, onRemove, error, showQuery = true }: {
  rule: IrRuleInstance;
  flags: string[];
  onChange: (value: IrPresetValue) => void;
  onRemove?: () => void;
  error?: string;
  showQuery?: boolean; // a rule of a group shows its query in the group's tooltip
}) => {
  const { t_i18n } = useFormatter();
  const [narrowing, setNarrowing] = useState(false);
  const def = getRule(rule.ruleKey);
  if (def.value === 'filters') {
    return (
      <Box>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5, mb: 1 }}>
          <Text as="span" variant="content-compact">
            <Box component="span" sx={{ color: 'text.secondary' }}>{t_i18n(def.sentence)}</Box>
          </Text>
          <Box sx={{ flex: 1 }} />
          {showQuery && (
            <IconButton aria-label={t_i18n('Query this rule runs')} tooltip={<QueryTooltip rule={rule} flags={flags} />}>
              <Icon name="info" size={16} />
            </IconButton>
          )}
          {onRemove && (
            <IconButton aria-label={t_i18n('Remove rule')} onClick={onRemove}>
              <Icon name="x" size={16} />
            </IconButton>
          )}
        </Box>
        <Suspense fallback={<Spinner size="sm" />}>
          <IrFilterBuilder value={rule.value.filters} onChange={(filters) => onChange({ ...rule.value, filters })} />
        </Suspense>
        {error && <ErrorText>{presetText(error, t_i18n)}</ErrorText>}
      </Box>
    );
  }
  // "any <type>" can be narrowed with filters: only the intrusion sets motivated by personal gain, say
  const canNarrow = def.value === 'entitiesOrType' && rule.value.types.length > 0;
  const showNarrowing = canNarrow && (narrowing || !!rule.value.filters);
  return (
    <Box>
      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5 }}>
        <Text as="span" variant="content-compact">
          <Box component="span" sx={{ color: 'text.secondary', whiteSpace: 'nowrap' }}>{t_i18n(def.sentence)}</Box>
        </Text>
        <Box sx={{ flex: 1, minWidth: 0, display: 'flex' }}>
          <Suspense fallback={<Spinner size="sm" />}>
            {/* without an "any <type>" choice, its narrowing filters go too */}
            <IrPresetValueField
              rule={def}
              flags={flags}
              value={rule.value}
              onChange={(value) => onChange(value.types.length === 0 && value.filters ? { ...value, filters: null } : value)}
            />
          </Suspense>
        </Box>
        {showQuery && (
          <IconButton aria-label={t_i18n('Query this rule runs')} tooltip={<QueryTooltip rule={rule} flags={flags} />}>
            <Icon name="info" size={16} />
          </IconButton>
        )}
        {onRemove && (
          <IconButton aria-label={t_i18n('Remove rule')} onClick={onRemove}>
            <Icon name="x" size={16} />
          </IconButton>
        )}
      </Box>
      {canNarrow && !showNarrowing && (
        <Box sx={{ mt: 0.5 }}>
          <FdsButton type="button" priority="tertiary" size="sm" startIcon={<Icon name="plus" size={16} />} onClick={() => setNarrowing(true)}>
            {t_i18n('Narrow with filters')}
          </FdsButton>
        </Box>
      )}
      {showNarrowing && (
        <Box sx={{ mt: 1, display: 'flex', flexDirection: 'column', gap: 0.75 }}>
          <Text as="span" variant="content-caption">
            <Box component="span" sx={{ color: 'text.secondary' }}>{t_i18n('Only those matching these filters')}</Box>
          </Text>
          <Suspense fallback={<Spinner size="sm" />}>
            <IrFilterBuilder value={rule.value.filters} onChange={(filters) => onChange({ ...rule.value, filters })} />
          </Suspense>
        </Box>
      )}
      {error && <ErrorText>{presetText(error, t_i18n)}</ErrorText>}
    </Box>
  );
};

// The name of an item: a text button with a pencil; the pencil turns it into a field (Enter or leaving it saves)
const IrItemName = ({ name, onRename }: { name: string; onRename: (name: string) => void }) => {
  const { t_i18n } = useFormatter();
  const [editing, setEditing] = useState<string | null>(null);
  const field = useRef<HTMLInputElement>(null);
  const cancelled = useRef(false);
  const isEditing = editing !== null;
  // the field takes the focus when the pencil opens it
  useEffect(() => {
    if (isEditing) {
      cancelled.current = false;
      field.current?.focus();
    }
  }, [isEditing]);
  if (editing !== null) {
    // a blur may follow Escape, when the field goes: the cancel wins
    const save = () => {
      if (!cancelled.current && editing.trim() !== name) onRename(editing);
      setEditing(null);
    };
    return (
      <Box sx={{ flex: 1, maxWidth: 520 }}>
        <Input
          aria-label={t_i18n('Name')}
          ref={field}
          value={editing}
          onChange={(e) => setEditing(e.target.value)}
          onBlur={save}
          onKeyDown={(e) => {
            if (e.key === 'Enter') save();
            if (e.key === 'Escape') {
              cancelled.current = true;
              setEditing(null);
            }
          }}
        />
      </Box>
    );
  }
  return (
    <Button variant="tertiary" size="small" title={t_i18n('Rename')} endIcon={<Icon name="pencil" size={16} />} onClick={() => setEditing(name)}>
      {name}
    </Button>
  );
};

// "+ Add rule" menus: the rules of the type, then (top level only) the advanced search criteria
export const IrAddRuleMenu = ({ heading, rules, trigger, onPick, onAdvanced, open, onOpenChange }: {
  heading: string;
  rules: IrPresetRule[];
  trigger: React.ReactElement; // a control that forwards its ref: the menu anchors on it
  onPick: (ruleKey: string) => void;
  onAdvanced?: () => void;
  open?: boolean;
  onOpenChange?: (open: boolean) => void;
}) => {
  const { t_i18n } = useFormatter();
  return (
    <Menu open={open} onOpenChange={onOpenChange} modal={false}>
      <MenuTrigger asChild>{trigger}</MenuTrigger>
      <MenuContent align="start" sideOffset={6} style={{ minWidth: 320, maxHeight: 420, overflowY: 'auto' }}>
        <MenuGroup>
          <MenuLabel>{heading}</MenuLabel>
          {rules.map((rule) => (
            <MenuItem key={rule.key} onSelect={() => onPick(rule.key)}>{`${t_i18n(rule.sentence)}…`}</MenuItem>
          ))}
        </MenuGroup>
        {onAdvanced && (
          <>
            <MenuSeparator />
            <MenuItem onSelect={onAdvanced}>
              <span style={{ display: 'flex', flexDirection: 'column', gap: 2, padding: '4px 0' }}>
                <span>{t_i18n('Advanced search criteria')}</span>
                <Text as="span" variant="content-caption">
                  <Box component="span" sx={{ color: 'text.secondary' }}>{t_i18n('Build your own rule with the standard OpenCTI filters.')}</Box>
                </Text>
              </span>
            </MenuItem>
          </>
        )}
      </MenuContent>
    </Menu>
  );
};

interface IrPresetItemCardProps {
  item: IrPresetItem;
  flags: string[];
  groupRules: IrPresetRule[];
  menuHeading: string;
  errors: IrItemError[];
  groupMenuOpen: boolean;
  autoOpenMenu?: boolean; // opens the menu of a new group, once its trigger is laid out
  onAutoOpened?: () => void;
  onGroupMenuOpenChange: (open: boolean) => void;
  onRename: (name: string) => void;
  onRemove: () => void;
  onRuleValue: (ruleId: string, value: IrPresetValue) => void;
  onRemoveGroupRule: (ruleId: string) => void;
  onAddGroupRule: (ruleKey: string) => void;
  onFilters: (filters: string | null) => void;
}

export const IrPresetItemCard = ({
  item,
  flags,
  groupRules,
  menuHeading,
  errors,
  groupMenuOpen,
  autoOpenMenu = false,
  onAutoOpened,
  onGroupMenuOpenChange,
  onRename,
  onRemove,
  onRuleValue,
  onRemoveGroupRule,
  onAddGroupRule,
  onFilters,
}: IrPresetItemCardProps) => {
  const { t_i18n } = useFormatter();
  // two frames: the card and its trigger are laid out before the menu measures where to open
  useEffect(() => {
    if (!autoOpenMenu) return undefined;
    let second = 0;
    const first = requestAnimationFrame(() => {
      second = requestAnimationFrame(() => onAutoOpened?.());
    });
    return () => {
      cancelAnimationFrame(first);
      cancelAnimationFrame(second);
    };
  }, [autoOpenMenu]);
  const ruleError = (ruleId: string) => errors.find((e) => e.ruleId === ruleId)?.message;
  const itemError = errors.find((e) => !e.ruleId)?.message;
  const isGroup = item.kind === 'group';
  return (
    <Box
      id={`ir-item-${item.id}`}
      sx={{
        border: '1px solid',
        borderColor: isGroup ? 'primary.main' : 'divider',
        bgcolor: isGroup ? (theme) => alpha(theme.palette.primary.main, 0.05) : undefined,
        borderRadius: 1,
        p: 2,
      }}
    >
      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1 }}>
        <IrItemName name={item.name} onRename={onRename} />
        {isGroup && (
          <Text as="span" variant="content-caption">
            <Box component="span" sx={{ color: 'text.secondary' }}>{`· ${t_i18n('Group: every rule in it must match')}`}</Box>
          </Text>
        )}
        {item.kind === 'group' && <GroupQueryButton rules={item.rules} flags={flags} />}
        <Box sx={{ flex: 1 }} />
        <IconButton aria-label={isGroup ? t_i18n('Remove group') : t_i18n('Remove rule')} onClick={onRemove}>
          <Icon name="x" size={16} />
        </IconButton>
      </Box>
      {item.kind === 'rule' && (
        <IrRuleRow rule={item.rule} flags={flags} onChange={(value) => onRuleValue(item.rule.id, value)} error={ruleError(item.rule.id)} />
      )}
      {item.kind === 'group' && (
        <>
          {item.rules.map((rule, index) => (
            <React.Fragment key={rule.id}>
              {index > 0 && <IrJoinDivider label={t_i18n('AND')} primary />}
              <Box sx={{ border: '1px solid', borderColor: 'divider', borderRadius: 1, p: 1.5, bgcolor: 'background.paper' }}>
                <IrRuleRow
                  rule={rule}
                  flags={flags}
                  onChange={(value) => onRuleValue(rule.id, value)}
                  onRemove={() => onRemoveGroupRule(rule.id)}
                  error={ruleError(rule.id)}
                  showQuery={false}
                />
              </Box>
            </React.Fragment>
          ))}
          <Box sx={{ mt: 1 }}>
            <IrAddRuleMenu
              heading={menuHeading}
              rules={groupRules}
              open={groupMenuOpen}
              onOpenChange={onGroupMenuOpenChange}
              onPick={onAddGroupRule}
              onAdvanced={() => onAddGroupRule(ADVANCED_RULE_KEY)}
              trigger={<FdsButton type="button" priority="tertiary" size="sm" startIcon={<Icon name="plus" size={16} />}>{t_i18n('Add rule to group')}</FdsButton>}
            />
          </Box>
        </>
      )}
      {item.kind === 'custom' && (
        <Suspense fallback={<Spinner size="sm" />}>
          <IrFilterBuilder value={item.filters} onChange={onFilters} />
        </Suspense>
      )}
      {itemError && <ErrorText>{presetText(itemError, t_i18n)}</ErrorText>}
    </Box>
  );
};
