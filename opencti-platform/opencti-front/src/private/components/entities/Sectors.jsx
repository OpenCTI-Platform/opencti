import React, { useState, useEffect } from 'react';
import * as PropTypes from 'prop-types';
import { useNavigate, useLocation } from 'react-router-dom';
import { QueryRenderer } from '../../../relay/environment';
import { buildViewParamsFromUrlAndStorage, saveViewParameters } from '../../../utils/ListParameters';
import { useFormatter } from '../../../components/i18n';
import SectorsLines, { sectorsLinesQuery } from './sectors/SectorsLines';
import SectorCreation from './sectors/SectorCreation';
import SearchInput from '../../../components/SearchInput';
import Security from '../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../utils/hooks/useGranted';
import Breadcrumbs from '../../../components/Breadcrumbs';
import useConnectedDocumentModifier from '../../../utils/hooks/useConnectedDocumentModifier';

const LOCAL_STORAGE_KEY = 'sectors';

const Sectors = () => {
  const { t_i18n } = useFormatter();
  const { setTitle } = useConnectedDocumentModifier();
  setTitle(t_i18n('Sectors | Entities'));
  const navigate = useNavigate();
  const location = useLocation();
  const params = buildViewParamsFromUrlAndStorage(
    navigate,
    location,
    LOCAL_STORAGE_KEY,
  );

  const [sectorsState, setSectorsState] = useState({
    searchTerm: params.searchTerm ?? '',
    openExports: false,
  });

  const saveView = () => {
    saveViewParameters(
      navigate,
      location,
      LOCAL_STORAGE_KEY,
      sectorsState,
    );
  };

  const handleSearch = (value) => {
    setSectorsState({ ...sectorsState,
      searchTerm: value,
    });
  };

  useEffect(() => {
    saveView();
  }, [sectorsState]);

  return (
    <>
      <Breadcrumbs variant="list" elements={[{ label: t_i18n('Entities') }, { label: t_i18n('Sectors'), current: true }]} />
      <div style={{ marginTop: -10 }}>
        <SearchInput
          variant="small"
          onSubmit={handleSearch}
          keyword={sectorsState.searchTerm}
          style={{ float: 'left' }}
        />
        <div style={{ float: 'right' }}>
          <Security needs={[KNOWLEDGE_KNUPDATE]}>
            <SectorCreation />
          </Security>
        </div>
      </div>
      <div className="clearfix" />
      <QueryRenderer
        query={sectorsLinesQuery}
        variables={{ count: 500 }}
        render={({ props }) => (
          <SectorsLines data={props} keyword={sectorsState.searchTerm} />
        )}
      />
    </>
  );
};

Sectors.propTypes = {
  t: PropTypes.func,
  navigate: PropTypes.func,
  location: PropTypes.object,
};

export default Sectors;
