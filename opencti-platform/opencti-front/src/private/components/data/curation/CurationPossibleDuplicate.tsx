import { useEffect, useState } from 'react';
import { graphql } from 'react-relay';
import { Link } from 'react-router';
import Tag from '@common/tag/Tag';
import { useTheme } from '@mui/styles';
import { useFormatter } from '../../../../components/i18n';
import type { Theme } from '../../../../components/Theme';
import { fetchQuery } from '../../../../relay/environment';
import useDraftContext from '../../../../utils/hooks/useDraftContext';
import { CURATION_PROPOSALS_PATH } from './curationUtils';
import { CurationPossibleDuplicateQuery$data } from './__generated__/CurationPossibleDuplicateQuery.graphql';

const possibleDuplicateQuery = graphql`
  query CurationPossibleDuplicateQuery($id: ID!) {
    curationProposalsForEntity(id: $id, status: [open]) {
      id
      proposal_kind
      confidence_score
    }
  }
`;

const DUPLICATE_KINDS = ['merge', 'alias'];

interface CurationPossibleDuplicateProps {
  entityId: string;
}

/**
 * "Possible duplicate" chip of an entity header, linking to its most confident open merge or alias proposal.
 * It never blocks the header: a failed lookup simply shows nothing.
 */
const CurationPossibleDuplicate = ({ entityId }: CurationPossibleDuplicateProps) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const draftContext = useDraftContext();
  const [proposal, setProposal] = useState<{ id: string; count: number } | null>(null);

  useEffect(() => {
    if (draftContext) return undefined;
    let active = true;
    fetchQuery(possibleDuplicateQuery, { id: entityId })
      .toPromise()
      .then((data) => {
        if (!active) return;
        const duplicates = ((data as CurationPossibleDuplicateQuery$data | undefined)?.curationProposalsForEntity ?? [])
          .filter((candidate) => DUPLICATE_KINDS.includes(candidate.proposal_kind));
        setProposal(duplicates.length > 0 ? { id: duplicates[0].id, count: duplicates.length } : null);
      })
      .catch(() => {
        if (active) setProposal(null);
      });
    return () => {
      active = false;
    };
  }, [entityId, draftContext]);

  if (!proposal) return null;
  const label = proposal.count > 1 ? `${t_i18n('Possible duplicate')} (${proposal.count})` : t_i18n('Possible duplicate');
  return (
    <Link
      to={`${CURATION_PROPOSALS_PATH}/${proposal.id}`}
      aria-label={t_i18n('Open the curation proposal of this possible duplicate')}
      data-testid="curation-possible-duplicate"
      style={{ textDecoration: 'none' }}
    >
      <Tag label={label} color={theme.palette.warn.main} />
    </Link>
  );
};

export default CurationPossibleDuplicate;
