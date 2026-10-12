import React from 'react';
import { useSearchParams } from 'react-router';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@filigran/design-system';
import { useFormatter } from '../../../../components/i18n';
import { CHANGES_SECTION_SEARCH_PARAM, ENTITY_CHANGES_SECTIONS, type EntityChangesSection, type EntityChangesSectionProps } from './entityChangesSections';

interface EntityChangesTabProps extends EntityChangesSectionProps {
  sections?: EntityChangesSection[];
}

/**
 * The Changes tab of an entity: one switch over the registered sections, the open one kept in the `section` search
 * parameter (other parameters of the URL are kept). An absent or unknown section opens the section the other
 * parameters of the link belong to (`matchesLink`), else the first one.
 */
const EntityChangesTab = ({ entityId, basePath, sections = ENTITY_CHANGES_SECTIONS }: EntityChangesTabProps) => {
  const { t_i18n } = useFormatter();
  const [searchParams, setSearchParams] = useSearchParams();
  const current = sections.find(({ key }) => key === searchParams.get(CHANGES_SECTION_SEARCH_PARAM))
    ?? sections.find(({ matchesLink }) => matchesLink?.(searchParams))
    ?? sections[0];
  if (!current) {
    return null;
  }
  const changeSection = (key: string) => {
    setSearchParams((params) => {
      const next = new URLSearchParams(params);
      next.set(CHANGES_SECTION_SEARCH_PARAM, key);
      return next;
    }, { replace: true });
  };
  return (
    <div data-testid="entity-changes-tab">
      <Tabs value={current.key} onValueChange={changeSection}>
        <TabsList className="mb-4" aria-label={t_i18n('Changes')}>
          {sections.map(({ key, label }) => (
            <TabsTrigger key={key} value={key} data-testid={`entity-changes-section-${key}`}>
              {t_i18n(label)}
            </TabsTrigger>
          ))}
        </TabsList>
        {sections.map(({ key, Component }) => (
          <TabsContent key={key} value={key}>
            <Component entityId={entityId} basePath={basePath} />
          </TabsContent>
        ))}
      </Tabs>
    </div>
  );
};

export default EntityChangesTab;
