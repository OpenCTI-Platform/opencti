import React from 'react';
import Breadcrumbs from '../../../components/Breadcrumbs';
import IngestionMenu from '@components/data/IngestionMenu';
import { useFormatter } from '../../../components/i18n';
import useConnectedDocumentModifier from '../../../utils/hooks/useConnectedDocumentModifier';

const IngestionCatalog = () => {
  const { t_i18n } = useFormatter();
  const { setTitle } = useConnectedDocumentModifier();
  setTitle(t_i18n('Catalog | Ingestion | Data'));
  return (
    <div style={{
      margin: 0,
      padding: '0 200px 50px 0',
    }}>
      <Breadcrumbs elements={[{ label: t_i18n('Data') }, { label: t_i18n('Ingestion') }, { label: t_i18n('Catalog'), current: true }]} />
      <IngestionMenu />
    </div>
  );
};

export default IngestionCatalog;
