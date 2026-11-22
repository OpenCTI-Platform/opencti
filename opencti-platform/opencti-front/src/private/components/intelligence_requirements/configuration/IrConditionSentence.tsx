import React, { ReactNode, useState } from 'react';
import { Input, Text, Tooltip, TooltipContent, TooltipTrigger } from '@filigran/design-system';
import Box from '@mui/material/Box';
import Button from '@common/button/Button';
import IconButton from '@common/button/IconButton';
import { CloseOutlined, DeleteOutlined } from '@mui/icons-material';
import { useFormatter } from '../../../../components/i18n';
import { emptyLink, emptyPathCondition, type IrConditionDraft, type IrGroupDraft, type IrPathConditionDraft } from './irConfigTypes';
import { groupSelectOptions, irGroupLabel, irRelationshipLabel, IR_RELATIONSHIP_TYPES } from './irConstants';
import { IrEntityPicker, IrMultiSelect, IrSelect } from './IrFields';
import IrFilterBuilder from './IrFilterBuilder';
import { SentenceToken } from './IrCriterionSentence';
import { countFilters } from './irSentence';

type Option = { value: string; label: string };
type TokenKey = 'types' | 'filters' | 'linkRels' | 'linkGroups' | 'pathRels' | 'pathDirection' | 'pathTargetRel' | 'pathTargets';

interface IrConditionSentenceProps {
  condition: IrConditionDraft;
  groups: IrGroupDraft[];
  typeOptions: Option[];
  onChange: (patch: Partial<IrConditionDraft>) => void;
  onDelete: () => void;
}

/**
 * A condition of the scope written as a sentence, with the relationship labels of the platform:
 * "Only if the Vulnerability is linked by targets to a member of Finance, and an entity that exploits it targets Finance".
 * It edits the same condition as the fields view.
 */
const IrConditionSentence = ({ condition, groups, typeOptions, onChange, onDelete }: IrConditionSentenceProps) => {
  const { t_i18n } = useFormatter();
  const [active, setActive] = useState<TokenKey | null>(null);
  const toggle = (key: TokenKey) => setActive((current) => (current === key ? null : key));

  const relationshipLabel = (rel: string) => irRelationshipLabel(t_i18n, rel);
  const relationshipOptions = IR_RELATIONSHIP_TYPES.map((r) => ({ value: r, label: relationshipLabel(r) }));
  const memberGroupOptions = groupSelectOptions(t_i18n, groups, (g) => g.kind !== 'keywords');
  const groupName = (id: string) => irGroupLabel(t_i18n, groups, id);
  const orList = (labels: string[], placeholder: string) => (labels.length > 0 ? labels.join(` ${t_i18n('or')} `) : placeholder);

  const token = (key: TokenKey, label: string, empty = false) => (
    <SentenceToken active={active === key} empty={empty} onClick={() => toggle(key)}>{label}</SentenceToken>
  );
  const remove = (label: string, onClick: () => void) => (
    <Tooltip>
      <TooltipTrigger asChild>
        <IconButton size="small" onClick={onClick} aria-label={label} style={{ marginLeft: 4 }}><CloseOutlined fontSize="small" /></IconButton>
      </TooltipTrigger>
      <TooltipContent>{label}</TooltipContent>
    </Tooltip>
  );

  const subject = condition.applies_to_types.length > 0
    ? `${t_i18n('the')} ${condition.applies_to_types.map((t) => t_i18n(`entity_${t}`)).join(', ')}`
    : t_i18n('the entity');
  const filterCount = countFilters(condition.filters);
  const path = condition.path_condition;
  const setPath = (patch: Partial<IrPathConditionDraft>) => path && onChange({ path_condition: { ...path, ...patch } });
  const pathTargets = path ? [...path.targets.map((t) => t.label), ...path.target_group_ids.map((g) => `${t_i18n('a member of')} ${groupName(g)}`)] : [];

  const parts: ReactNode[] = [];
  if (condition.filters !== null) {
    parts.push(
      <span key="filters">
        {`${t_i18n('it matches')} `}
        {token('filters', filterCount > 0 ? t_i18n('{count, plural, one {# filter} other {# filters}}', { values: { count: filterCount } }) : t_i18n('which filters?'), filterCount === 0)}
        {remove(t_i18n('Remove the filters'), () => onChange({ filters: null }))}
      </span>,
    );
  }
  if (condition.link) {
    const { link } = condition;
    parts.push(
      <span key="link">
        {`${t_i18n('it is linked by')} `}
        {token('linkRels', orList(link.relationship_types.map(relationshipLabel), t_i18n('which relationship?')), link.relationship_types.length === 0)}
        {` ${t_i18n('to a member of')} `}
        {token('linkGroups', orList(link.group_ids.map(groupName), t_i18n('which group?')), link.group_ids.length === 0)}
        {` ${t_i18n('(either way)')}`}
        {remove(t_i18n('Remove the link'), () => onChange({ link: null }))}
      </span>,
    );
  }
  if (path) {
    const rels = token('pathRels', orList(path.relationship_types.map(relationshipLabel), t_i18n('which relationship?')), path.relationship_types.length === 0);
    let hop: ReactNode;
    if (path.direction === 'incoming') hop = <>{`${t_i18n('an entity that')} `}{rels}{` ${t_i18n('it')}`}</>;
    else if (path.direction === 'outgoing') hop = <>{`${t_i18n('it')} `}{rels}{` ${t_i18n('an entity that')}`}</>;
    else hop = <>{`${t_i18n('an entity linked to it by')} `}{rels}{` ${t_i18n('(either way)')}`}</>;
    parts.push(
      <span key="path">
        {hop}
        {token('pathDirection', '⇄', false)}
        {path.direction === 'outgoing' ? ' ' : ` ${t_i18n('and')} `}
        {token('pathTargetRel', relationshipLabel(path.target_relationship_type))}
        {' '}
        {token('pathTargets', orList(pathTargets, t_i18n('what?')), pathTargets.length === 0)}
        {remove(t_i18n('Remove the path'), () => onChange({ path_condition: null }))}
      </span>,
    );
  }

  const addFilters = () => {
    onChange({ filters: '' });
    setActive('filters');
  };
  const addLink = () => {
    onChange({ link: emptyLink() });
    setActive('linkGroups');
  };
  const addPath = () => {
    onChange({ path_condition: emptyPathCondition() });
    setActive('pathRels');
  };

  let editor: ReactNode = null;
  if (active === 'types') {
    editor = <IrMultiSelect label={t_i18n('Applies to (empty = every type of the criterion)')} values={condition.applies_to_types} options={typeOptions} onChange={(v) => onChange({ applies_to_types: v })} />;
  } else if (active === 'filters' && condition.filters !== null) {
    editor = <IrFilterBuilder value={condition.filters || null} onChange={(filters) => onChange({ filters: filters ?? '' })} />;
  } else if (active === 'linkRels' && condition.link) {
    const { link } = condition;
    editor = <IrMultiSelect label={t_i18n('Relationships')} values={link.relationship_types} options={relationshipOptions} onChange={(v) => onChange({ link: { ...link, relationship_types: v } })} />;
  } else if (active === 'linkGroups' && condition.link) {
    const { link } = condition;
    editor = <IrMultiSelect label={t_i18n('Subject groups')} values={link.group_ids} options={memberGroupOptions} onChange={(v) => onChange({ link: { ...link, group_ids: v } })} />;
  } else if (active === 'pathRels' && path) {
    editor = <IrMultiSelect label={t_i18n('Relationships of the first hop')} values={path.relationship_types} options={relationshipOptions} onChange={(v) => setPath({ relationship_types: v })} />;
  } else if (active === 'pathDirection' && path) {
    editor = (
      <IrSelect
        label={t_i18n('Direction of the first hop')}
        value={path.direction}
        options={[
          { value: 'incoming', label: t_i18n('an entity that … it') },
          { value: 'outgoing', label: t_i18n('it … an entity that') },
          { value: 'both', label: t_i18n('either way') },
        ]}
        onChange={(v) => setPath({ direction: v as IrPathConditionDraft['direction'] })}
      />
    );
  } else if (active === 'pathTargetRel' && path) {
    editor = <IrSelect label={t_i18n('Relationship of that entity')} value={path.target_relationship_type} options={relationshipOptions} onChange={(v) => setPath({ target_relationship_type: v })} />;
  } else if (active === 'pathTargets' && path) {
    editor = (
      <Box sx={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: 2 }}>
        <IrEntityPicker label={t_i18n('Entities')} value={path.targets} onChange={(targets) => setPath({ targets })} />
        <IrMultiSelect label={t_i18n('or a member of')} values={path.target_group_ids} options={memberGroupOptions} onChange={(v) => setPath({ target_group_ids: v })} />
      </Box>
    );
  }

  return (
    <Box sx={{ border: '1px solid', borderColor: 'divider', borderRadius: 1, p: 1.5, mb: 1, position: 'relative' }}>
      <Box sx={{ position: 'absolute', top: 4, right: 4 }}>
        <IconButton aria-label={t_i18n('Delete')} onClick={onDelete}><DeleteOutlined fontSize="small" /></IconButton>
      </Box>
      <Box sx={{ pr: 5, mb: 1, maxWidth: 360 }}>
        <Input label={t_i18n('Condition name')} value={condition.name} onChange={(e) => onChange({ name: e.target.value })} />
      </Box>
      <Text as="div" variant="content-base">
        {`${t_i18n('For')} `}
        {token('types', subject)}
        {`, ${t_i18n('only if')} `}
        {parts.length > 0
          ? parts.map((part, i) => <React.Fragment key={i}>{i > 0 ? `, ${t_i18n('and')} ` : ''}{part}</React.Fragment>)
          : <Text as="span" variant="content-caption" style={{ opacity: 0.7 }}>{t_i18n('… add what it must meet')}</Text>}
      </Text>
      {editor && <Box sx={{ mt: 1.5, maxWidth: 640 }}>{editor}</Box>}
      <Box sx={{ display: 'flex', gap: 1, mt: 1, flexWrap: 'wrap' }}>
        {condition.filters === null && <Button variant="tertiary" size="small" onClick={addFilters}>{t_i18n('+ filters on the entity')}</Button>}
        {!condition.link && <Button variant="tertiary" size="small" onClick={addLink}>{t_i18n('+ direct link to a subject group')}</Button>}
        {!path && <Button variant="tertiary" size="small" onClick={addPath}>{t_i18n('+ path through another entity')}</Button>}
      </Box>
    </Box>
  );
};

export default IrConditionSentence;
