import React, { FunctionComponent } from 'react';
import { Link } from 'react-router-dom';
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
      return <div style={{ paddingTop: 6 }}>
        {t('There are not any configurations set yet')}
        <div style={{ paddingTop: 6 }}>
          {
            isCsvMapperUpdater
              ? <Link to="/dashboard/data/processing/csv_mapper">{t('Create a CSV Mapper configuration')}</Link>
              : t('Please contact an administrator')
          }
        </div>
      </div>;
    case undefined: // In case there isn't any connector selected
      return <></>;
    default:
      return <></>;
  }
};

export default ManageImportConnectorMessage;
