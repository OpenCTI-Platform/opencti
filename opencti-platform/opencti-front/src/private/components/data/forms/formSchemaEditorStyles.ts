import Button from '@common/button/Button';
import { styled } from '@mui/material/styles';

export const Container = styled('div')({
  marginTop: 20,
});

export const TabPanel = styled('div')({
  marginTop: 20,
});

export const EntityHeader = styled('div')({
  display: 'flex',
  justifyContent: 'space-between',
});

export const FieldHeader = styled('div')({
  display: 'flex',
  justifyContent: 'space-between',
  alignItems: 'center',
});

export const AddButton = styled(Button)({
  '&&': {
    marginTop: 10,
  },
});

export const tabPanelSx = {
  marginTop: '20px',
};

export const entitySectionSx = {
  padding: '20px',
  border: '1px solid var(--border-elevation-subtle)',
  borderRadius: '4px',
};

export const fieldGroupSx = {
  padding: '15px',
  borderRadius: '4px',
  border: '1px solid var(--border-elevation-subtle)',
};

export const fieldTitleSx = {
  fontWeight: 600,
  fontSize: '14px',
};

export const relationshipGroupSx = {
  padding: '15px',
  borderRadius: '4px',
  border: '1px solid var(--border-elevation-subtle)',
};

export const alertSx = {
  marginBottom: '20px',
};
