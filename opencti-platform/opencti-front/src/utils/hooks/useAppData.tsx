import React, { ReactNode, createContext, useContext } from 'react';
import { MetricsDefinition } from 'src/components/dataGrid/dataTableUtils';
import { resolveLink } from '../Entity';
import useSchema from './useSchema';

export type ComputeLinkNode = {
  id: string;
  entity_type: string;
  relationship_type?: string;
  from?: { entity_type: string; id: string };
  to?: { entity_type: string; id: string };
  type?: string;
};

export type AppData = {
  computeLink: (node: ComputeLinkNode) => string | undefined;
  metricsDefinition: MetricsDefinition[];
};

const useComputeLinkFn = () => {
  const { isRelationship } = useSchema();
  const computeLink = (node: ComputeLinkNode): string | undefined => {
    let redirectLink;
    if (node.relationship_type === 'stix-sighting-relationship' && node.from) {
      redirectLink = `${resolveLink(node.from.entity_type)}/${
        node.from.id
      }/knowledge/sightings/${node.id}`;
    } else if (node.relationship_type) {
      if (node.from && !isRelationship(node.from.entity_type)) {
        redirectLink = `${resolveLink(node.from.entity_type)}/${
          node.from.id
        }/knowledge/relations/${node.id}`;
      } else if (node.to && !isRelationship(node.to.entity_type)) {
        redirectLink = `${resolveLink(node.to.entity_type)}/${
          node.to.id
        }/knowledge/relations/${node.id}`;
      } else {
        redirectLink = undefined;
      }
    } else if (node.entity_type === 'Workspace') {
      redirectLink = `${resolveLink(node.type)}/${node.id}`;
    } else {
      redirectLink = `${resolveLink(node.entity_type)}/${node.id}`;
    }
    return redirectLink;
  };

  return computeLink;
};

const AppDataContext = createContext<AppData | null>(null);

export const useAppData = (): AppData => {
  const appData = useContext(AppDataContext);
  if (!appData) {
    throw new Error('useAppData must be used within AppDataProvider');
  }
  return appData;
};

// Convenience hook for backward compatibility
export const useComputeLink = (): AppData['computeLink'] => {
  const { computeLink } = useAppData();
  return computeLink;
};

const PrivateAppDataProvider: React.FC<{
  children: ReactNode;
  metricsDefinition: MetricsDefinition[];
}> = ({ children, metricsDefinition }) => {
  const computeLink = useComputeLinkFn();

  const appData: AppData = {
    computeLink,
    metricsDefinition,
  };

  return (
    <AppDataContext.Provider value={appData}>
      {children}
    </AppDataContext.Provider>
  );
};

export const AppDataProvider = ({
  isPublicRoute,
  metricsDefinition = [],
  children,
}: {
  isPublicRoute: boolean;
  metricsDefinition?: MetricsDefinition[];
  children: ReactNode;
}) => {
  if (isPublicRoute) {
    const appData: AppData = {
      computeLink: () => '',
      metricsDefinition: [],
    };

    return (
      <AppDataContext.Provider value={appData}>
        {children}
      </AppDataContext.Provider>
    );
  }

  return (
    <PrivateAppDataProvider metricsDefinition={metricsDefinition}>
      {children}
    </PrivateAppDataProvider>
  );
};
