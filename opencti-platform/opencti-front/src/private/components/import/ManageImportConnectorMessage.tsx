import React, { FunctionComponent } from 'react';
import { Link } from 'react-router-dom';
import Box from '@mui/material/Box';
import { useFormatter } from '../../../components/i18n';
import useGranted, { TAXIIAPI_SETCSVMAPPERS } from '../../../utils/hooks/useGranted';

interface ManageImportConnectorMessageProps {
  name: string;
}

const ManageImportConnectorMessage: FunctionComponent<ManageImportConnectorMessageProps> = ({ name }) => {
  const { t } = useFormatter();
  const isCsvMapperUpdater = useGranted([TAXIIAPI_SETCSVMAPPERS]);
  switch (name) {
    case 'ImportCsv':
      return <Box sx={{ paddingTop: '8px' }}>
        {t('There are not any configurations set yet')}
        <div>
          {
            isCsvMapperUpdater
              ? <Link to="/dashboard/data/processing/csv_mapper">{t('Create a CSV Mapper configuration')}</Link>
              : t('Please contact an administrator')
          }
        </div>
      </Box>;
    case undefined: // In case there isn't any connector selected
      return <></>;
    default:
      return <></>;
  }
};

export default ManageImportConnectorMessage;
