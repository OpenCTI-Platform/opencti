import React, { FunctionComponent } from 'react';
import List from '@mui/material/List';
import ListItemButton from '@mui/material/ListItemButton';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import { AssignmentOutlined } from '@mui/icons-material';
import { useNavigate } from 'react-router-dom';
import { StixCoreObjectFormsFormsQuery$data } from '@components/common/stix_core_objects/__generated__/StixCoreObjectFormsFormsQuery.graphql';
import Drawer from '../drawer/Drawer';
import { useFormatter } from '../../../../components/i18n';

interface StixCoreObjectFormSelectorProps {
  data: StixCoreObjectFormsFormsQuery$data;
  open: boolean;
  handleClose: () => void;
}

const StixCoreObjectFormSelector: FunctionComponent<StixCoreObjectFormSelectorProps> = ({ data, open, handleClose }) => {
  const { t_i18n } = useFormatter();
  const navigate = useNavigate();
  return (
    <Drawer
      open={open}
      onClose={handleClose}
      title={t_i18n('Select a form')}
    >
      {({ onClose }) => {
        const handleFormSelect = (formId: string) => {
          navigate(`/dashboard/data/ingestion/forms/${formId}`);
          onClose();
        };
        return (
          <List>
            {(data?.forms?.edges ?? []).map((formEdge) => (
              <ListItemButton
                key={formEdge.node.id}
                onClick={() => handleFormSelect(formEdge.node.id)}
                divider
              >
                <ListItemIcon>
                  <AssignmentOutlined color="primary" />
                </ListItemIcon>
                <ListItemText
                  primary={formEdge.node.name}
                  secondary={formEdge.node.description || null}
                />
              </ListItemButton>
            ))}
          </List>
        );
      }}
    </Drawer>
  );
};

export default StixCoreObjectFormSelector;
