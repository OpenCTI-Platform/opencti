import React, { FunctionComponent } from 'react';
import { Link } from 'react-router-dom';
import Box from '@mui/material/Box';
import { styled } from '@mui/material/styles';
import { useFormatter } from '../../../components/i18n';
import useGranted, { TAXIIAPI_SETCSVMAPPERS } from '../../../utils/hooks/useGranted';

interface ManageImportConnectorMessageProps {
  name: string
}
const WarningText = styled('span')(({ theme }) => ({
  color: theme.palette.error.main,
}));

const ManageImportConnectorMessage: FunctionComponent<ManageImportConnectorMessageProps> = ({ name }) => {
  const { t } = useFormatter();
  const isCsvMapperUpdater = useGranted([TAXIIAPI_SETCSVMAPPERS]);
  switch (name) {
    case 'ImportCsv':
      return <Box sx={{ paddingTop: '8px' }}>
        <WarningText >{t('There are not any configurations set yet')}</WarningText>
        <div>
          {
            isCsvMapperUpdater
              ? <Link to="/dashboard/data/processing/csv_mapper">{t('Create a CSV Mapper configuration')}</Link>
              : <WarningText>{t('Please contact an administrator')}</WarningText>
          }
        </div>
      </Box>;
    case undefined: // In case there isn't any connector selected
      return null;
    default:
      return null;
  }
};

export default ManageImportConnectorMessage;
