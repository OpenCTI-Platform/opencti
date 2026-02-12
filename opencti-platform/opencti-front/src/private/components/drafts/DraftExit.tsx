import { graphql } from 'relay-runtime';
import { useNavigate } from 'react-router-dom';
import Button from '../../../components/common/button/Button';
import useSwitchDraft from './useSwitchDraft';
import { useFormatter } from '../../../components/i18n';
import { useFragment } from 'react-relay';
import { DraftExitFragment$key } from '@components/drafts/__generated__/DraftExitFragment.graphql';

const draftFragment = graphql`
  fragment DraftExitFragment on DraftWorkspace {
    entity_id
  }
`;

interface DraftExitProps {
  data: DraftExitFragment$key;
}

const DraftExit = ({ data }: DraftExitProps) => {
  const navigate = useNavigate();
  const { t_i18n } = useFormatter();
  const { exitDraft } = useSwitchDraft();
  const { entity_id } = useFragment(draftFragment, data);

  const onExitDraft = () => {
    exitDraft({
      onCompleted: () => {
        if (entity_id) {
          navigate(`/dashboard/id/${entity_id}`);
        } else {
          navigate('/dashboard/data/import/draft');
        }
      },
    });
  };

  return (
    <Button variant="secondary" onClick={onExitDraft}>
      {t_i18n('Exit draft')}
    </Button>
  );
};

export default DraftExit;
