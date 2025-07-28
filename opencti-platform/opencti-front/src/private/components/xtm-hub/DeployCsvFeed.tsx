import React, { useContext, useEffect, useRef, useState } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import { IngestionCsvImportQuery$data } from '@components/data/ingestionCsv/__generated__/IngestionCsvImportQuery.graphql';
import { csvFeedImportQuery } from '@components/data/ingestionCsv/IngestionCsvImport';
import { IngestionCsvEditionFragment_ingestionCsv$data } from '@components/data/ingestionCsv/__generated__/IngestionCsvEditionFragment_ingestionCsv.graphql';
import { IngestionCsvCreationContainer } from '@components/data/ingestionCsv/IngestionCsvCreation';
import { fetchQuery, MESSAGING$ } from '../../../relay/environment';
import Loader from '../../../components/Loader';
import { UserContext } from '../../../utils/hooks/useAuth';
import { RelayError } from '../../../relay/relayTypes';
import { useFormatter } from '../../../components/i18n';

const DeployCsvFeed = () => {
  const navigate = useNavigate();
  const { settings } = useContext(UserContext);
  const { serviceInstanceId, fileId } = useParams();
  const [ingestCSVData, setIngestCSVData] = useState<IngestionCsvImportQuery$data['csvFeedAddInputFromImport'] | undefined>(undefined);
  const [open, setOpen] = useState<boolean>(false);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const inputFileRef = useRef<HTMLInputElement>(null);
  const { t_i18n } = useFormatter();

  const handleFileImport = (file: File) => {
    if (file) {
      fetchQuery(csvFeedImportQuery, { file })
        .toPromise()
        .then((data) => {
          const { csvFeedAddInputFromImport } = data as IngestionCsvImportQuery$data;
          setIngestCSVData(csvFeedAddInputFromImport);
          setOpen(true);
          if (inputFileRef.current) {
            inputFileRef.current.value = '';
          }
          setIsLoading(false);
        })
        .catch((e) => {
          const { errors } = (e as unknown as RelayError).res;
          MESSAGING$.notifyError(errors.at(0)?.message);
        });
    }
  };
  useEffect(() => {
    const fetchData = async () => {
      try {
        const response = await fetch(
          `${settings?.platform_xtmhub_url}/document/get/${serviceInstanceId}/${fileId}`,
          {
            method: 'GET',
            credentials: 'include',
          },
        );

        const blob = await response.blob();
        const file = new File([blob], 'downloaded.json', {
          type: 'application/json',
        });

        handleFileImport(file);
      } catch (e) {
        navigate('/dashboard/data/ingestion/csv');
        MESSAGING$.notifyError('An error occured while importing CSV Feed configuration.');
      }
    };
    fetchData();
  }, [serviceInstanceId, fileId]);

  return <>{isLoading ? (
    <Loader/>
  ) : (
    <IngestionCsvCreationContainer
      ingestionCsvData={{
        ...ingestCSVData,
      } as unknown as IngestionCsvEditionFragment_ingestionCsv$data}
      triggerButton={false}
      handleClose={() => setOpen(false)}
      open={open}
      paginationOptions={{}}
      drawerSettings={{
        title: t_i18n('Import a CSV Feed'),
        button: t_i18n('Create'),
      }}
    />
  )
  };</>;
};
export default DeployCsvFeed;
