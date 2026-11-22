import React, { ReactNode, useState } from 'react';
import { Input, Text } from '@filigran/design-system';
import Box from '@mui/material/Box';
import Button from '@common/button/Button';
import IconButton from '@common/button/IconButton';
import { DeleteOutlined } from '@mui/icons-material';
import { useFormatter } from '../../../../components/i18n';
import type { IrCriterionDraft, IrGroupDraft } from './irConfigTypes';
import { groupSelectOptions, irGroupLabel, IR_KEYWORD_FIELDS } from './irConstants';
import { IrMultiSelect, IrSelect } from './IrFields';
import IrFilterBuilder from './IrFilterBuilder';
import { criterionToPhrases, criterionToStarts, impliedPhrases, IN_REQUIREMENT_START, phrasesToCriterion, relationPhraseOptions, startsToCriterion } from './irSentence';

type Option = { value: string; label: string };
type TokenKey = 'mode' | 'types' | 'relations' | 'starts' | 'groups' | 'fields';

// A clickable part of the sentence: it opens its field under the sentence
export const SentenceToken = ({ active, empty, onClick, children }: { active: boolean; empty: boolean; onClick: () => void; children: ReactNode }) => (
  <Box
    component="button"
    type="button"
    onClick={onClick}
    sx={{
      display: 'inline',
      font: 'inherit',
      cursor: 'pointer',
      border: '1px solid',
      borderColor: active ? 'primary.main' : 'divider',
      borderStyle: empty ? 'dashed' : 'solid',
      borderRadius: 1,
      px: 0.75,
      py: 0.25,
      mx: 0.25,
      bgcolor: active ? 'action.selected' : 'action.hover',
      color: empty ? 'text.secondary' : 'primary.main',
      lineHeight: 2.2,
    }}
  >
    {children}
  </Box>
);

interface IrCriterionSentenceProps {
  criterion: IrCriterionDraft;
  groups: IrGroupDraft[];
  typeOptions: Option[];
  onChange: (patch: Partial<IrCriterionDraft>) => void;
  onDelete: () => void;
  conditions: ReactNode; // the conditions of the scope, rendered by the form as in the fields view
}

/**
 * A scope criterion written as a sentence: "Bring in the Malware, Tool used by North Korean actors".
 * It edits the same criterion as the fields view: only the way it reads and is edited changes.
 */
const IrCriterionSentence = ({ criterion, groups, typeOptions, onChange, onDelete, conditions }: IrCriterionSentenceProps) => {
  const { t_i18n } = useFormatter();
  const [active, setActive] = useState<TokenKey | null>(null);
  const [advanced, setAdvanced] = useState(false);
  const toggle = (key: TokenKey) => setActive((current) => (current === key ? null : key));

  const groupName = (id: string) => irGroupLabel(t_i18n, groups, id);
  const list = (labels: string[], placeholder: string) => (labels.length > 0 ? labels.join(', ') : placeholder);

  const modeOptions = [
    { value: 'auto', label: t_i18n('Bring in automatically') },
    { value: 'propose', label: t_i18n('Propose') },
    { value: 'off', label: t_i18n('Ignore (off)') },
  ];
  const phraseOptions = relationPhraseOptions().map((o) => ({ value: o.value, label: t_i18n(o.label) }));
  const phrases = criterionToPhrases(criterion);
  const implied = impliedPhrases(phrases);
  const startOptions = [
    ...groupSelectOptions(t_i18n, groups, (g) => g.kind !== 'keywords'),
    { value: IN_REQUIREMENT_START, label: t_i18n('the entities already in the requirement') },
  ];
  const memberGroupOptions = groupSelectOptions(t_i18n, groups, (g) => g.kind !== 'keywords');
  const keywordGroupOptions = groupSelectOptions(t_i18n, groups, (g) => g.kind === 'keywords');
  const fieldOptions = IR_KEYWORD_FIELDS.map((f) => ({ value: f, label: t_i18n(f) }));

  const typesLabel = list(criterion.target_types.map((t) => t_i18n(`entity_${t}`)), t_i18n('entities of any type'));
  const modeLabel = modeOptions.find((o) => o.value === criterion.mode)?.label ?? criterion.mode;

  const token = (key: TokenKey, label: string, empty = false) => (
    <SentenceToken active={active === key} empty={empty} onClick={() => toggle(key)}>{label}</SentenceToken>
  );

  let sentence: ReactNode;
  if (criterion.kind === 'graph') {
    const starts = criterionToStarts(criterion);
    sentence = (
      <>
        {token('mode', modeLabel)}
        {` ${t_i18n('the')} `}
        {token('types', typesLabel, criterion.target_types.length === 0)}
        {token('relations', list(phrases.map((p) => phraseOptions.find((o) => o.value === p)?.label ?? p), t_i18n('linked how?')), phrases.length === 0)}
        {token('starts', list(starts.map((s) => (s === IN_REQUIREMENT_START ? t_i18n('the entities already in the requirement') : groupName(s))), t_i18n('starting from what?')), starts.length === 0)}
      </>
    );
  } else if (criterion.kind === 'attribute') {
    sentence = (
      <>
        {token('mode', modeLabel)}
        {` ${t_i18n('the')} `}
        {token('types', typesLabel, criterion.target_types.length === 0)}
        {` ${t_i18n('that are members of')} `}
        {token('groups', list(criterion.from_group_ids.map(groupName), t_i18n('any subject group')), criterion.from_group_ids.length === 0)}
      </>
    );
  } else {
    sentence = (
      <>
        {token('mode', modeLabel)}
        {` ${t_i18n('the')} `}
        {token('types', typesLabel, criterion.target_types.length === 0)}
        {` ${t_i18n('whose')} `}
        {token('fields', list(criterion.keyword_fields.map((f) => t_i18n(f)), t_i18n('texts')), criterion.keyword_fields.length === 0)}
        {` ${t_i18n('mention a keyword of')} `}
        {token('groups', list(criterion.from_group_ids.map(groupName), t_i18n('which keywords?')), criterion.from_group_ids.length === 0)}
        {` ${t_i18n('(or that a container mentioning one contains)')}`}
      </>
    );
  }

  let editor: ReactNode = null;
  if (active === 'mode') {
    editor = <IrSelect label={t_i18n('Mode')} value={criterion.mode} options={modeOptions} onChange={(v) => onChange({ mode: v as IrCriterionDraft['mode'] })} />;
  } else if (active === 'types') {
    editor = <IrMultiSelect label={t_i18n('Entity types that enter')} values={criterion.target_types} options={typeOptions} onChange={(v) => onChange({ target_types: v })} />;
  } else if (active === 'relations') {
    editor = (
      <IrMultiSelect
        label={t_i18n('How they are linked to the starting points')}
        values={phrases}
        options={phraseOptions}
        onChange={(v) => onChange(phrasesToCriterion(v))}
      />
    );
  } else if (active === 'starts') {
    editor = (
      <IrMultiSelect
        label={t_i18n('Starting points')}
        values={criterionToStarts(criterion)}
        options={startOptions}
        onChange={(v) => onChange(startsToCriterion(v))}
      />
    );
  } else if (active === 'groups') {
    editor = (
      <IrMultiSelect
        label={criterion.kind === 'keywords' ? t_i18n('Keyword groups') : t_i18n('Subject groups')}
        values={criterion.from_group_ids}
        options={criterion.kind === 'keywords' ? keywordGroupOptions : memberGroupOptions}
        onChange={(v) => onChange({ from_group_ids: v })}
      />
    );
  } else if (active === 'fields') {
    editor = <IrMultiSelect label={t_i18n('Search in')} values={criterion.keyword_fields} options={fieldOptions} onChange={(v) => onChange({ keyword_fields: v })} />;
  }

  return (
    <Box sx={{ border: '1px solid', borderColor: 'divider', borderRadius: 1, p: 2, mb: 1.5, position: 'relative' }}>
      <Box sx={{ position: 'absolute', top: 8, right: 8 }}>
        <IconButton aria-label={t_i18n('Delete')} onClick={onDelete}><DeleteOutlined fontSize="small" /></IconButton>
      </Box>
      <Box sx={{ pr: 5, mb: 1.5, maxWidth: 420 }}>
        <Input label={t_i18n('Criterion name')} value={criterion.name} onChange={(e) => onChange({ name: e.target.value })} />
      </Box>
      <Text as="div" variant="content-base">{sentence}</Text>
      {implied.length > 0 && (
        <Text as="div" variant="content-caption" style={{ marginTop: 4, opacity: 0.8 }}>
          {`${t_i18n('Mixed directions: the engine also evaluates')} ${implied.map((p) => phraseOptions.find((o) => o.value === p)?.label ?? p).join(', ')}`}
        </Text>
      )}
      {editor && <Box sx={{ mt: 1.5, maxWidth: 640 }}>{editor}</Box>}
      {conditions}
      <Box sx={{ mt: 1.5 }}>
        <Button variant="tertiary" size="small" onClick={() => setAdvanced((a) => !a)}>
          {advanced ? t_i18n('Hide advanced options') : t_i18n('Advanced options')}
        </Button>
      </Box>
      {advanced && (
        <Box sx={{ mt: 1.5 }}>
          <Box sx={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 2, mb: 2 }}>
            <IrSelect
              label={t_i18n('Kind')}
              value={criterion.kind}
              options={[{ value: 'graph', label: t_i18n('Path in the graph') }, { value: 'attribute', label: t_i18n('Members or attributes (zero hop)') }, { value: 'keywords', label: t_i18n('Keywords') }]}
              onChange={(v) => {
                setActive(null);
                onChange({ kind: v as IrCriterionDraft['kind'] });
              }}
            />
            {criterion.kind === 'graph' && (
              <IrMultiSelect label={t_i18n('Only start from these entity types (optional)')} values={criterion.from_types} options={typeOptions} onChange={(v) => onChange({ from_types: v })} />
            )}
          </Box>
          <Text as="div" variant="content-caption" style={{ marginBottom: 8, opacity: 0.8 }}>{t_i18n('Target filters (optional)')}</Text>
          <IrFilterBuilder value={criterion.target_filters} onChange={(filters) => onChange({ target_filters: filters })} />
        </Box>
      )}
    </Box>
  );
};

export default IrCriterionSentence;
