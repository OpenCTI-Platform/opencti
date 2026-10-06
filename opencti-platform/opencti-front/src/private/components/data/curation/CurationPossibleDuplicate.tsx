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

const possibleDuplicateQuery = graphql`
  query CurationPossibleDuplicateQuery($id: ID!) {
    curationProposalsForEntity(id: $id, status: [open]) {
      id
      proposal_kind
      confidence_score
      subject_ids
      subject_names
      created_at
      explanation {
        title { template values text }
      }
    }
  }
`;

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

type Proposals = CurationPossibleDuplicateQuery$data['curationProposalsForEntity'];

const toHeaderProposal = (proposals: Proposals, entityId: string): HeaderProposal | null => {
  if (proposals.length === 0) return null;
  const [first] = proposals;
  return {
    proposalId: first.id,
    count: proposals.length,
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
    fetchQuery(possibleDuplicateQuery, { id: entityId })
      .toPromise()
      .then((data) => {
        if (!active) return;
        const proposals = (data as CurationPossibleDuplicateQuery$data | undefined)?.curationProposalsForEntity ?? [];
        setFound({
          entityId,
          duplicate: toHeaderProposal(proposals.filter((proposal) => proposal.proposal_kind === 'merge'), entityId),
          aliases: toHeaderProposal(proposals.filter((proposal) => proposal.proposal_kind === 'alias'), entityId),
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
