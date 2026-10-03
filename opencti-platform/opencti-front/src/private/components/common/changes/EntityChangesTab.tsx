import React, { Suspense } from 'react';
import { useSearchParams } from 'react-router';
import { Tabs, TabsList, TabsTrigger } from '@filigran/design-system';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import { useFormatter } from '../../../../components/i18n';
import { ENTITY_CHANGES_VIEWS, type EntityChangesView } from './entityChangesViews';

interface EntityChangesTabProps {
  entityId: string;
  views?: EntityChangesView[];
}

/** The Changes tab of an entity: one switch over the registered views, the current one kept in the `view` parameter. */
const EntityChangesTab = ({ entityId, views = ENTITY_CHANGES_VIEWS }: EntityChangesTabProps) => {
  const { t_i18n } = useFormatter();
  const [searchParams, setSearchParams] = useSearchParams();
  const current = views.find((view) => view.key === searchParams.get('view')) ?? views[0];
  if (!current) {
    return null;
  }
  const changeView = (key: string) => {
    const next = new URLSearchParams(searchParams);
    next.set('view', key);
    setSearchParams(next, { replace: true });
  };
  const CurrentView = current.component;
  return (
    <div data-testid="entity-changes-tab">
      <Tabs value={current.key} onValueChange={changeView} panels="external">
        <TabsList className="mb-6" aria-label={t_i18n('Changes')}>
          {views.map((view) => (
            <TabsTrigger key={view.key} value={view.key} data-testid={`entity-changes-view-${view.key}`}>
              {t_i18n(view.label)}
            </TabsTrigger>
          ))}
        </TabsList>
      </Tabs>
      <Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
        <CurrentView entityId={entityId} />
      </Suspense>
    </div>
  );
};

export default EntityChangesTab;
