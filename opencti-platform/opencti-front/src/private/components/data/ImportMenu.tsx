import React from 'react';
import { Link, useLocation } from 'react-router-dom';
import { Tabs, TabsList, TabsTrigger } from '@filigran/design-system';
import { useFormatter } from '../../../components/i18n';

const ImportMenu = () => {
  const { t_i18n } = useFormatter();
  const location = useLocation();

  return (
    <Tabs value={location.pathname} panels="external">
      <TabsList className="pb-6">
        <TabsTrigger value="/dashboard/data/import/file" asChild>
          <Link to="/dashboard/data/import/file">{t_i18n('Global files')}</Link>
        </TabsTrigger>
        <TabsTrigger value="/dashboard/data/import/draft" asChild>
          <Link to="/dashboard/data/import/draft">{t_i18n('Drafts')}</Link>
        </TabsTrigger>
        <TabsTrigger value="/dashboard/data/import/workbench" asChild>
          <Link to="/dashboard/data/import/workbench">{t_i18n('Analyst workbenches')}</Link>
        </TabsTrigger>
      </TabsList>
    </Tabs>
  );
};

export default ImportMenu;
