import React, { FunctionComponent, useState } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import { buildViewParamsFromUrlAndStorage, saveViewParameters } from '../../../utils/ListParameters';
import Breadcrumbs from '../../../components/Breadcrumbs';
import { useFormatter } from '../../../components/i18n';
import SearchInput from '../../../components/SearchInput';
import { QueryRenderer } from '../../../relay/environment';
import Security from '../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../utils/hooks/useGranted';
import NarrativeCreation from './narratives/NarrativeCreation';
import NarrativesLines, { narrativesLinesQuery } from './narratives/NarrativesLines';
import useConnectedDocumentModifier from '../../../utils/hooks/useConnectedDocumentModifier';

const Narratives: FunctionComponent = () => {
  const navigate = useNavigate();
  const location = useLocation();
  const { t_i18n } = useFormatter();
  const { setTitle } = useConnectedDocumentModifier();
  setTitle(t_i18n('Narratives | Techniques'));

  const LOCAL_STORAGE_KEY = 'narratives';
  const params = buildViewParamsFromUrlAndStorage(navigate, location, LOCAL_STORAGE_KEY);
  const [searchTerm, setSearchTerm] = useState<string>(params.searchTerm ?? '');
  // const [searchTerm, setSearchTerm] = useState<string>('');
  const [openExports] = useState<boolean>(false);

  const saveView = () => {
    saveViewParameters(
      navigate,
      location,
      LOCAL_STORAGE_KEY,
      {
        searchTerm,
        openExports,
      },
    );
  };

  const handleSearch = (value: string) => {
    setSearchTerm(value);
    saveView();
  };

  return (
    <>
      <Breadcrumbs variant="list" elements={[{ label: t_i18n('Techniques') }, { label: t_i18n('Narratives'), current: true }]} />
      <div style={{ float: 'left', marginRight: 20 }}>
        <SearchInput
          variant="small"
          onSubmit={handleSearch.bind(this)}
          keyword={searchTerm}
        />
      </div>
      <div className="clearfix" />
      <QueryRenderer
        query={narrativesLinesQuery}
        variables={{ count: 500 }}
        render={({ props } : { props: string }) => (
          <NarrativesLines data={props} keyword={searchTerm} />
        )}
      />
      <Security needs={[KNOWLEDGE_KNUPDATE]}>
        <NarrativeCreation />
      </Security>
    </>
  );
};

export default Narratives;
