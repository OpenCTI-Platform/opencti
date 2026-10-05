import { Fragment, type ReactNode } from 'react';
import { Link } from 'react-router';
import Box from '@mui/material/Box';
import Typography from '@mui/material/Typography';
import { useTheme } from '@mui/styles';
import Label from '@common/label/Label';
import Tag from '@common/tag/Tag';
import { useFormatter } from '../../../../components/i18n';
import type { Theme } from '../../../../components/Theme';
import { resolveLink } from '../../../../utils/Entity';
import { parseJsonObject } from './curationUtils';

export interface CurationExplanationMessage {
  readonly template: string;
  readonly values: string;
  readonly text: string;
}

export interface CurationExplanationData {
  readonly title: CurationExplanationMessage;
  readonly changes: ReadonlyArray<{
    readonly field: CurationExplanationMessage;
    readonly before: ReadonlyArray<string>;
    readonly after: ReadonlyArray<string>;
  }>;
  readonly evidence: ReadonlyArray<{
    readonly message: CurationExplanationMessage;
    readonly entities: ReadonlyArray<{ readonly id: string; readonly name: string; readonly entity_type: string }>;
    readonly sources: ReadonlyArray<{ readonly name: string; readonly reference?: string | null; readonly url?: string | null }>;
  }>;
  readonly why: CurationExplanationMessage;
  readonly confidence: { readonly score: number; readonly level: string; readonly meaning: CurationExplanationMessage };
  readonly on_accept: CurationExplanationMessage;
  readonly on_reject: CurationExplanationMessage;
  readonly on_later: CurationExplanationMessage;
  readonly reversible: boolean;
}

const DATE_TIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}/;
const SINGLE_PLACEHOLDER = /^\{(\w+)\}$/;
const MAX_TAGS = 30;

/**
 * Translates an explanation message the platform built: its template is the translation key, and its values are
 * formatted by name - a name ending in "Type" is an entity type, in "Field" an attribute, an ISO date-time a date.
 */
export const useExplanationTranslator = () => {
  const { t_i18n, fldt } = useFormatter();
  const fieldLabels: Record<string, string> = {
    first_seen: t_i18n('First seen'),
    last_seen: t_i18n('Last seen'),
    valid_from: t_i18n('Valid from'),
    valid_until: t_i18n('Valid until'),
    start_time: t_i18n('Start time'),
    stop_time: t_i18n('Stop time'),
  };
  const translatedOr = (key: string, fallback: string) => {
    const translated = t_i18n(key);
    return translated === key ? fallback : translated;
  };
  const formatValue = (key: string, raw: unknown): string | number => {
    if (typeof raw === 'number') return raw;
    const text = String(raw ?? '');
    if (key.endsWith('Type')) return translatedOr(`entity_${text}`, translatedOr(`relationship_${text}`, text));
    if (key === 'field' || key.endsWith('Field')) return fieldLabels[text] ?? t_i18n(text);
    if (DATE_TIME.test(text)) return fldt(text);
    return text;
  };
  return (message: CurationExplanationMessage | null | undefined): string => {
    if (!message) return '';
    const raw = parseJsonObject(message.values) ?? {};
    const values = Object.fromEntries(Object.entries(raw).map(([key, entry]) => [key, formatValue(key, entry)]));
    const single = SINGLE_PLACEHOLDER.exec(message.template);
    if (single) return String(values[single[1]] ?? message.text);
    return t_i18n(message.template, { values });
  };
};

const sameName = (left: string, right: string) => left.trim().toLowerCase() === right.trim().toLowerCase();

interface TagListProps {
  values: ReadonlyArray<string>;
  highlighted?: ReadonlyArray<string>;
  empty: string;
  testId: string;
}

const TagList = ({ values, highlighted = [], empty, testId }: TagListProps) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  if (values.length === 0) {
    return <Typography variant="body2" color={theme.palette.text?.secondary} data-testid={testId}>{empty}</Typography>;
  }
  return (
    <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5 }} data-testid={testId}>
      {values.slice(0, MAX_TAGS).map((value) => {
        const isNew = highlighted.some((name) => sameName(name, value));
        return <Tag key={value} label={['Yes', 'No'].includes(value) ? t_i18n(value) : value} color={isNew ? theme.palette.success.main : undefined} />;
      })}
      {values.length > MAX_TAGS && <Typography variant="body2">{t_i18n('and {count} more', { values: { count: values.length - MAX_TAGS } })}</Typography>}
    </Box>
  );
};

interface CurationProposalExplanationProps {
  explanation: CurationExplanationData;
  /** Replaces the changes the platform computed, for a change whose result depends on a choice made on screen. */
  changes?: ReactNode;
  /** The value chosen on screen for a change the platform leaves to the analyst (the attribution to keep). */
  chosen?: string | null;
  /** The why sentence is shown elsewhere (the proposal header). */
  hideWhy?: boolean;
}

/**
 * The explanation of a curation proposal, in the order an analyst decides with it: what changes, the evidence, why,
 * the confidence and what each decision does.
 */
const CurationProposalExplanation = ({ explanation, changes, chosen, hideWhy = false }: CurationProposalExplanationProps) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const translate = useExplanationTranslator();
  const levelColors: Record<string, string | undefined> = { high: theme.palette.success.main, medium: theme.palette.warn.main, low: theme.palette.error.main };
  const section = (title: string, testId: string, content: ReactNode) => (
    <Box component="section" sx={{ display: 'flex', flexDirection: 'column', gap: 0.75 }} data-testid={testId}>
      <Label>{title}</Label>
      {content}
    </Box>
  );
  const renderChanges = () => {
    if (changes) return changes;
    if (explanation.changes.length === 0) {
      return <Typography variant="body2">{t_i18n('Nothing changes in the knowledge.')}</Typography>;
    }
    return (
      <Box sx={{ display: 'grid', gridTemplateColumns: 'minmax(120px, max-content) 1fr 1fr', columnGap: 2, rowGap: 1, alignItems: 'start' }}>
        <span />
        <Typography variant="caption" color={theme.palette.text?.secondary}>{t_i18n('Before')}</Typography>
        <Typography variant="caption" color={theme.palette.text?.secondary}>{t_i18n('After')}</Typography>
        {explanation.changes.map((change, index) => {
          const after = change.after.length === 0 && chosen ? [chosen] : change.after;
          const added = after.filter((value) => !change.before.some((previous) => sameName(previous, value)));
          return (
            <Box key={`${change.field.template}-${index}`} sx={{ display: 'contents' }} data-testid="curation-explanation-change">
              <Typography variant="body2" sx={{ fontWeight: 'fontWeightBold' }}>{translate(change.field)}</Typography>
              <TagList values={change.before} empty={t_i18n('None')} testId="curation-explanation-before" />
              <TagList values={after} highlighted={added} empty={t_i18n('To choose')} testId="curation-explanation-after" />
            </Box>
          );
        })}
      </Box>
    );
  };
  return (
    <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }} data-testid="curation-explanation">
      {section(t_i18n('What changes'), 'curation-explanation-changes', renderChanges())}
      {section(t_i18n('Evidence'), 'curation-explanation-evidence', (
        <Box component="ul" sx={{ margin: 0, paddingLeft: 2.5, display: 'flex', flexDirection: 'column', gap: 0.5 }}>
          {explanation.evidence.map((item, index) => (
            <Typography component="li" variant="body2" key={`${item.message.template}-${index}`}>
              {translate(item.message)}
              {item.sources.map((source) => (
                <span key={`${source.name}-${source.reference ?? ''}`}>
                  {' - '}
                  {source.url ? (
                    <a href={source.url} target="_blank" rel="noopener noreferrer">{[source.name, source.reference].filter(Boolean).join(' ')}</a>
                  ) : [source.name, source.reference].filter(Boolean).join(' ')}
                </span>
              ))}
              {item.entities.length > 0 && (
                <span data-testid="curation-explanation-evidence-entities">
                  {' - '}
                  {item.entities.map((entity, position) => {
                    const link = resolveLink(entity.entity_type);
                    return (
                      <Fragment key={entity.id}>
                        {position > 0 && ', '}
                        {link ? <Link to={`${link}/${entity.id}`}>{entity.name}</Link> : entity.name}
                      </Fragment>
                    );
                  })}
                </span>
              )}
            </Typography>
          ))}
        </Box>
      ))}
      {!hideWhy && section(t_i18n('Why'), 'curation-explanation-why', <Typography variant="body2">{translate(explanation.why)}</Typography>)}
      {section(t_i18n('Confidence'), 'curation-explanation-confidence', (
        <Typography variant="body2" sx={{ color: levelColors[explanation.confidence.level] }}>{translate(explanation.confidence.meaning)}</Typography>
      ))}
      {section(t_i18n('What happens when you decide'), 'curation-explanation-outcomes', (
        <Box component="dl" sx={{ margin: 0, display: 'grid', gridTemplateColumns: 'max-content 1fr', columnGap: 2, rowGap: 0.5, typography: 'body2' }}>
          <Box component="dt" sx={{ fontWeight: 'fontWeightBold' }}>{t_i18n('Accept')}</Box>
          <Box component="dd" sx={{ margin: 0 }}>{translate(explanation.on_accept)}</Box>
          <Box component="dt" sx={{ fontWeight: 'fontWeightBold' }}>{t_i18n('Reject')}</Box>
          <Box component="dd" sx={{ margin: 0 }}>{translate(explanation.on_reject)}</Box>
          <Box component="dt" sx={{ fontWeight: 'fontWeightBold' }}>{t_i18n('Decide later')}</Box>
          <Box component="dd" sx={{ margin: 0 }}>{translate(explanation.on_later)}</Box>
        </Box>
      ))}
    </Box>
  );
};

export default CurationProposalExplanation;
