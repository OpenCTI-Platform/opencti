import { useEffect, useState } from 'react';
import { graphql } from 'react-relay';
import { Link } from 'react-router';
import { Chip, Tooltip, TooltipContent, TooltipTrigger } from '@filigran/design-system';
import { useFormatter } from '../../../../components/i18n';
import { fetchQuery } from '../../../../relay/environment';
import useDraftContext from '../../../../utils/hooks/useDraftContext';
import { truncate } from '../../../../utils/String';
import { CURATION_PROPOSALS_PATH, formatPercent } from './curationUtils';
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
    }
  }
`;

const DUPLICATE_KINDS = ['merge', 'alias'];
const MAX_NAME_LENGTH = 40;

interface CurationPossibleDuplicateProps {
  entityId: string;
}

interface PossibleDuplicate {
  proposalId: string;
  count: number;
  otherName: string | null;
  confidence: number;
  proposedAt: string;
}

/**
 * "Possible duplicate" chip of an entity header, linking to its most confident open merge or alias proposal.
 * It never blocks the header: a failed lookup simply shows nothing.
 */
const CurationPossibleDuplicate = ({ entityId }: CurationPossibleDuplicateProps) => {
  const { t_i18n, fldt, rd } = useFormatter();
  const draftContext = useDraftContext();
  const [duplicate, setDuplicate] = useState<PossibleDuplicate | null>(null);

  useEffect(() => {
    if (draftContext) return undefined;
    let active = true;
    fetchQuery(possibleDuplicateQuery, { id: entityId })
      .toPromise()
      .then((data) => {
        if (!active) return;
        const duplicates = ((data as CurationPossibleDuplicateQuery$data | undefined)?.curationProposalsForEntity ?? [])
          .filter((candidate) => DUPLICATE_KINDS.includes(candidate.proposal_kind));
        if (duplicates.length === 0) {
          setDuplicate(null);
          return;
        }
        const [first] = duplicates;
        const otherName = first.subject_names.find((_, index) => first.subject_ids[index] !== entityId) ?? null;
        setDuplicate({ proposalId: first.id, count: duplicates.length, otherName, confidence: first.confidence_score, proposedAt: first.created_at });
      })
      .catch(() => {
        if (active) setDuplicate(null);
      });
    return () => {
      active = false;
    };
  }, [entityId, draftContext]);

  if (!duplicate) return null;
  const describe = (name: string | null) => {
    if (duplicate.count > 1) {
      return t_i18n('{count, plural, one {# possible duplicate} other {# possible duplicates}}', { values: { count: duplicate.count } });
    }
    return name ? t_i18n('Possible duplicate of {name}', { values: { name } }) : t_i18n('Possible duplicate');
  };
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <Link
          to={`${CURATION_PROPOSALS_PATH}/${duplicate.proposalId}`}
          aria-label={t_i18n('Open the curation proposal of this possible duplicate')}
          data-testid="curation-possible-duplicate"
          style={{ textDecoration: 'none' }}
        >
          <Chip severity="medium" size="sm" label={describe(duplicate.otherName ? truncate(duplicate.otherName, MAX_NAME_LENGTH) : null)} />
        </Link>
      </TooltipTrigger>
      <TooltipContent>
        {describe(duplicate.otherName)}
        <br />
        {t_i18n('{confidence} confidence, proposed {relative} ({date})', {
          values: { confidence: formatPercent(duplicate.confidence), relative: rd(duplicate.proposedAt), date: fldt(duplicate.proposedAt) },
        })}
      </TooltipContent>
    </Tooltip>
  );
};

export default CurationPossibleDuplicate;
