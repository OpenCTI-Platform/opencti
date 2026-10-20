import React from 'react';
import { Link, useLocation } from 'react-router';
import { Tabs, TabsList, TabsTrigger } from '@filigran/design-system';
import { useFormatter } from '../../../components/i18n';
import { menuEntries } from './ImportMenu.entries';

const ImportMenu = () => {
  const { t_i18n } = useFormatter();
  const location = useLocation();

  return (
    <Tabs value={location.pathname} panels="external">
      <TabsList className="mb-6">
        {menuEntries.map(({ path, label }) => (
          <TabsTrigger key={path} value={path} asChild>
            <Link to={path}>{t_i18n(label)}</Link>
          </TabsTrigger>
        ))}
      </TabsList>
    </Tabs>
  );
};

export default ImportMenu;
