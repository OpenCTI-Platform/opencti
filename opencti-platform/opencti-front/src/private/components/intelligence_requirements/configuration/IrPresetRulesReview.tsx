import React from 'react';
import { Icon, Text } from '@filigran/design-system';
import Box from '@mui/material/Box';
import { alpha } from '@mui/material/styles';
import Button from '@common/button/Button';
import IconButton from '@common/button/IconButton';
import { useFormatter } from '../../../../components/i18n';
import { getRule } from './irPresetRules';
import { valueLabels, type IrPresetItem, type IrRuleInstance } from './irPresetDraft';
import { GroupQueryButton, IrJoinDivider, QueryTooltip, presetText } from './IrPresetItemCard';
import { countFilters } from './irSentence';

// The review step shows the rules as they read, not as they are stored: a rule is changed on the criteria step.

const ReadOnlyRule = ({ rule, flags, showQuery = true }: { rule: IrRuleInstance; flags: string[]; showQuery?: boolean }) => {
  const { t_i18n } = useFormatter();
  const def = getRule(rule.ruleKey);
  const values = valueLabels(def, rule.value, (text) => presetText(text, t_i18n));
  return (
    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
      <Text as="span" variant="content-compact">
        <Box component="span" sx={{ color: 'text.secondary' }}>{t_i18n(def.sentence)}</Box>
        {values.length > 0 && <Box component="span" sx={{ fontWeight: 600 }}>{` ${values.join(', ')}`}</Box>}
        {def.value === 'filters' && (
          <Box component="span" sx={{ fontWeight: 600 }}>{` · ${t_i18n('{count, plural, one {# filter} other {# filters}}', { values: { count: countFilters(rule.value.filters) } })}`}</Box>
        )}
      </Text>
      {showQuery && (
        <IconButton aria-label={t_i18n('Query this rule runs')} tooltip={<QueryTooltip rule={rule} flags={flags} />}>
          <Icon name="info" size={16} />
        </IconButton>
      )}
    </Box>
  );
};

const IrPresetRulesReview = ({ items, flags, onEdit }: {
  items: IrPresetItem[];
  flags: string[];
  onEdit: (itemId: string) => void; // back to the criteria step, on this item
}) => {
  const { t_i18n } = useFormatter();
  return (
    <Box>
      {items.map((item, index) => {
        const isGroup = item.kind === 'group';
        return (
          <React.Fragment key={item.id}>
            {index > 0 && <IrJoinDivider label={t_i18n('or')} />}
            <Box
              sx={{
                border: '1px solid',
                borderColor: isGroup ? 'primary.main' : 'divider',
                bgcolor: isGroup ? (theme) => alpha(theme.palette.primary.main, 0.05) : undefined,
                borderRadius: 1,
                p: 2,
              }}
            >
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1 }}>
                <Text as="span" variant="content-compact-bold">{item.name}</Text>
                {isGroup && (
                  <Text as="span" variant="content-caption">
                    <Box component="span" sx={{ color: 'text.secondary' }}>{`· ${t_i18n('Group: every rule in it must match')}`}</Box>
                  </Text>
                )}
                {item.kind === 'group' && <GroupQueryButton rules={item.rules} flags={flags} />}
                <Box sx={{ flex: 1 }} />
                <Button variant="tertiary" size="small" startIcon={<Icon name="pencil" size={16} />} onClick={() => onEdit(item.id)}>
                  {t_i18n('Edit')}
                </Button>
              </Box>
              {item.kind === 'rule' && <ReadOnlyRule rule={item.rule} flags={flags} />}
              {item.kind === 'group' && item.rules.map((rule, ruleIndex) => (
                <React.Fragment key={rule.id}>
                  {ruleIndex > 0 && <IrJoinDivider label={t_i18n('AND')} primary />}
                  <ReadOnlyRule rule={rule} flags={flags} showQuery={false} />
                </React.Fragment>
              ))}
              {item.kind === 'custom' && (
                <Text as="span" variant="content-compact">
                  <Box component="span" sx={{ color: 'text.secondary' }}>{t_i18n('Advanced search criteria')}</Box>
                  <Box component="span" sx={{ fontWeight: 600 }}>{` · ${t_i18n('{count, plural, one {# filter} other {# filters}}', { values: { count: countFilters(item.filters) } })}`}</Box>
                </Text>
              )}
            </Box>
          </React.Fragment>
        );
      })}
    </Box>
  );
};

export default IrPresetRulesReview;
