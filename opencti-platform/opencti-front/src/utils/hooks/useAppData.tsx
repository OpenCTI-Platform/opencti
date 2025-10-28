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

export type AppDataProps = {
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
      if (node.from && !isRelationship(node.from.entity_type)) { // 'from' not restricted and not a relationship
        redirectLink = `${resolveLink(node.from.entity_type)}/${
          node.from.id
        }/knowledge/relations/${node.id}`;
      } else if (node.to && !isRelationship(node.to.entity_type)) { // if 'from' is restricted or a relationship, redirect to the knowledge relationship tab of 'to'
        redirectLink = `${resolveLink(node.to.entity_type)}/${
          node.to.id
        }/knowledge/relations/${node.id}`;
      } else {
        redirectLink = undefined; // no redirection if from and to are restricted
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

const AppDataContext = createContext<AppDataProps | null>(null);

export const useAppData = (): AppDataProps => {
  const appData = useContext(AppDataContext);
  if (!appData) {
    throw new Error('useAppData must be used within AppDataProvider');
  }
  return appData;
};

export const useComputeLink = (): AppDataProps['computeLink'] => {
  const { computeLink } = useAppData();
  return computeLink;
};

type PrivateAppDataProviderProps = {
  children: ReactNode;
  metricsDefinition: MetricsDefinition[];
};

const PrivateAppDataProvider: React.FC<PrivateAppDataProviderProps> = ({ children, metricsDefinition }) => {
  const computeLink = useComputeLinkFn();

  const appData: AppDataProps = {
    computeLink,
    metricsDefinition,
  };

  return (
    <AppDataContext.Provider value={appData}>
      {children}
    </AppDataContext.Provider>
  );
};

type AppDataProviderProps = {
  isPublicRoute: boolean;
  metricsDefinition?: MetricsDefinition[];
  children: ReactNode;
};

export const AppDataProvider = ({
  isPublicRoute,
  metricsDefinition = [],
  children,
}: AppDataProviderProps) => {
  if (isPublicRoute) {
    const appData: AppDataProps = {
      computeLink: () => '',
      metricsDefinition,
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
