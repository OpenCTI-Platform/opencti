import IconButton from '@common/button/IconButton';
import { TravelExploreOutlined } from '@mui/icons-material';
import Tooltip from '@mui/material/Tooltip';
import useCreateInvestigationFromSelection from './useCreateInvestigationFromSelection';

interface InvestigationCreationFromSelectionProps {
  disabled: boolean;
  entityIds: string[];
  title?: string;
}

const InvestigationCreationFromSelection = ({
  disabled,
  entityIds,
  title = 'Start an investigation',
}: InvestigationCreationFromSelectionProps) => {
  const { createInvestigation, creating } = useCreateInvestigationFromSelection();

  return (
    <Tooltip title={title}>
      <span>
        <IconButton
          aria-label={title}
          disabled={disabled || creating}
          onClick={() => createInvestigation(entityIds)}
          size="small"
        >
          <TravelExploreOutlined fontSize="small" />
        </IconButton>
      </span>
    </Tooltip>
  );
};

export default InvestigationCreationFromSelection;
