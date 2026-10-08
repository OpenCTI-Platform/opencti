import { useEffect, useState } from 'react';
import { graphql } from 'react-relay';
import { Link } from 'react-router';
import { Chip, Tooltip, TooltipContent, TooltipTrigger } from '@filigran/design-system';
import { useFormatter } from '../../../../components/i18n';
import { fetchQuery } from '../../../../relay/environment';
import useDraftContext from '../../../../utils/hooks/useDraftContext';
import { truncate } from '../../../../utils/String';
import { CURATION_PROPOSALS_PATH, formatPercent } from './curationUtils';
import { type CurationExplanationMessage, useExplanationTranslator } from './CurationProposalExplanation';
import { CurationPossibleDuplicateQuery$data } from './__generated__/CurationPossibleDuplicateQuery.graphql';

// Each kind is read on its own, its most confident proposal with the number of all of them.
const possibleDuplicateQuery = graphql`
  query CurationPossibleDuplicateQuery($merges: FilterGroup, $aliases: FilterGroup) {
    merges: curationProposals(first: 1, orderBy: confidence_score, orderMode: desc, filters: $merges) {
      pageInfo {
        globalCount
      }
      edges {
        node {
          id
          confidence_score
          subject_ids
          subject_names
          created_at
          explanation {
            title { template values text }
          }
        }
      }
    }
    aliases: curationProposals(first: 1, orderBy: confidence_score, orderMode: desc, filters: $aliases) {
      pageInfo {
        globalCount
      }
      edges {
        node {
          id
          confidence_score
          subject_ids
          subject_names
          created_at
          explanation {
            title { template values text }
          }
        }
      }
    }
  }
`;

const openProposalsOf = (entityId: string, kind: 'merge' | 'alias') => ({
  mode: 'and',
  filters: [
    { key: ['subject_ids'], values: [entityId], operator: 'eq', mode: 'or' },
    { key: ['proposal_status'], values: ['open'], operator: 'eq', mode: 'or' },
    { key: ['proposal_kind'], values: [kind], operator: 'eq', mode: 'or' },
  ],
  filterGroups: [],
} as const);

const MAX_NAME_LENGTH = 40;

interface CurationPossibleDuplicateProps {
  entityId: string;
}

interface HeaderProposal {
  proposalId: string;
  count: number;
  otherName: string | null;
  confidence: number;
  proposedAt: string;
  title: CurationExplanationMessage;
}

interface HeaderProposals {
  duplicate: HeaderProposal | null;
  aliases: HeaderProposal | null;
}

const NO_PROPOSALS: HeaderProposals = { duplicate: null, aliases: null };

/** The proposals of the entity they were loaded for. */
interface LoadedProposals extends HeaderProposals {
  entityId: string | null;
}

type Proposals = CurationPossibleDuplicateQuery$data['merges'];

const toHeaderProposal = (proposals: Proposals | undefined, entityId: string): HeaderProposal | null => {
  const first = proposals?.edges[0]?.node;
  if (!proposals || !first) return null;
  return {
    proposalId: first.id,
    count: proposals.pageInfo.globalCount,
    otherName: first.subject_names.find((_, index) => first.subject_ids[index] !== entityId) ?? null,
    confidence: first.confidence_score,
    proposedAt: first.created_at,
    title: first.explanation.title,
  };
};

/**
 * Curation chips of an entity header: "Possible duplicate" for its most confident open merge proposal, "Aliases to
 * review" for its open alias proposal - an alias proposal adds names, it never says the entity is duplicated. Each
 * links to its proposal. They never block the header: a failed lookup simply shows nothing.
 */
const CurationPossibleDuplicate = ({ entityId }: CurationPossibleDuplicateProps) => {
  const { t_i18n, fldt, rd } = useFormatter();
  const translate = useExplanationTranslator();
  const draftContext = useDraftContext();
  const [found, setFound] = useState<LoadedProposals>({ entityId: null, ...NO_PROPOSALS });

  useEffect(() => {
    if (draftContext) return undefined;
    let active = true;
    fetchQuery(possibleDuplicateQuery, { merges: openProposalsOf(entityId, 'merge'), aliases: openProposalsOf(entityId, 'alias') })
      .toPromise()
      .then((data) => {
        if (!active) return;
        const result = data as CurationPossibleDuplicateQuery$data | undefined;
        setFound({
          entityId,
          duplicate: toHeaderProposal(result?.merges, entityId),
          aliases: toHeaderProposal(result?.aliases, entityId),
        });
      })
      .catch(() => {
        if (active) setFound({ entityId, ...NO_PROPOSALS });
      });
    return () => {
      active = false;
    };
  }, [entityId, draftContext]);

  // Proposals loaded for the previous entity never show while those of this one load, nor in a draft.
  const { duplicate, aliases } = found.entityId === entityId && !draftContext ? found : NO_PROPOSALS;
  const describeDuplicate = (proposal: HeaderProposal, name: string | null) => {
    if (proposal.count > 1) {
      return t_i18n('{count, plural, one {# possible duplicate} other {# possible duplicates}}', { values: { count: proposal.count } });
    }
    return name ? t_i18n('Possible duplicate of {name}', { values: { name } }) : t_i18n('Possible duplicate');
  };
  const chip = (proposal: HeaderProposal, label: string, ariaLabel: string, testId: string) => (
    <Tooltip key={testId}>
      <TooltipTrigger asChild>
        <Link to={`${CURATION_PROPOSALS_PATH}/${proposal.proposalId}`} aria-label={ariaLabel} data-testid={testId} style={{ textDecoration: 'none' }}>
          <Chip severity="medium" size="sm" label={label} />
        </Link>
      </TooltipTrigger>
      <TooltipContent>
        {translate(proposal.title)}
        <br />
        {t_i18n('{confidence} confidence, proposed {relative} ({date})', {
          values: { confidence: formatPercent(proposal.confidence), relative: rd(proposal.proposedAt), date: fldt(proposal.proposedAt) },
        })}
      </TooltipContent>
    </Tooltip>
  );
  return (
    <>
      {duplicate && chip(
        duplicate,
        describeDuplicate(duplicate, duplicate.otherName ? truncate(duplicate.otherName, MAX_NAME_LENGTH) : null),
        t_i18n('Open the curation proposal of this possible duplicate'),
        'curation-possible-duplicate',
      )}
      {aliases && chip(aliases, t_i18n('Aliases to review'), t_i18n('Open the curation proposal of these aliases'), 'curation-aliases-to-review')}
    </>
  );
};

export default CurationPossibleDuplicate;
