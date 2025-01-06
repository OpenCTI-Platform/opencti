import React, { FunctionComponent, useState } from 'react';
import Tooltip from '@mui/material/Tooltip';
import ToggleButton from '@mui/material/ToggleButton';
import { PrecisionManufacturingOutlined } from '@mui/icons-material';
import { StixCoreObjectEnrollPlaybookLinesQuery$data } from '@components/common/stix_core_objects/__generated__/StixCoreObjectEnrollPlaybookLinesQuery.graphql';
import Drawer from '../drawer/Drawer';
import { QueryRenderer } from '../../../../relay/environment';
import StixCoreObjectEnrollPlaybookLines, { stixCoreObjectEnrollPlaybookLinesQuery } from './StixCoreObjectEnrollPlaybookLines';
import { useFormatter } from '../../../../components/i18n';

interface StixCoreObjectEnrollPlaybookLinesProps {
  stixCoreObjectId: string,
  handleClose: () => void,
  open: boolean,
}

const StixCoreObjectEnrollPlaybook: FunctionComponent<StixCoreObjectEnrollPlaybookLinesProps> = ({ stixCoreObjectId, handleClose, open }) => {
  const [openDrawer, setOpenDrawer] = useState(false);
  const { t_i18n } = useFormatter();
  const handleOpenEnrollPlaybook = () => {
    setOpenDrawer(true);
  };
  const handleCloseEnrollPlaybook = () => {
    setOpenDrawer(false);
  };
  return (
    <>
      {!handleClose && (
        <Tooltip title={t_i18n('Enroll in playbook')}>
          <ToggleButton
            onClick={handleOpenEnrollPlaybook}
            value="enrich"
            size="small"
            style={{ marginRight: 3 }}
          >
            <PrecisionManufacturingOutlined fontSize="small" color="primary" />
          </ToggleButton>
        </Tooltip>
      )}
      <Drawer
        open={open || openDrawer}
        onClose={handleClose || handleCloseEnrollPlaybook}
        title={t_i18n('Available playbooks')}
      >
        <QueryRenderer
          query={stixCoreObjectEnrollPlaybookLinesQuery}
          variables={{ id: stixCoreObjectId }}
          render={({ props: queryProps }: { props: StixCoreObjectEnrollPlaybookLinesQuery$data }) => {
            if (queryProps && queryProps.playbooksForEntity) {
              return (
                <StixCoreObjectEnrollPlaybookLines id={stixCoreObjectId} playbooksForEntity={queryProps.playbooksForEntity} />
              );
            }
            return <div />;
          }}
        />
      </Drawer>
    </>
  );
};

export default StixCoreObjectEnrollPlaybook;
