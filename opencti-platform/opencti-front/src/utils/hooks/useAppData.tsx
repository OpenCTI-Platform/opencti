import React, { ReactNode, createContext, useContext } from 'react';
import { MetricsDefinition } from 'src/components/dataGrid/dataTableUtils';
import { resolveLink } from '../Entity';
import useSchema from './useSchema';

export type ComputeLinkNode = {
  id?: string;
  entity_type?: string;
  relationship_type?: string;
  from?: { entity_type?: string; id?: string } | null;
  to?: { entity_type?: string; id?: string } | null;
  type?: string;
  resultOf?: { id: string } | null;
};

export type AppDataProps = {
  computeLink: (node: ComputeLinkNode) => string | undefined;
  metricsDefinition: MetricsDefinition[];
};

export const useComputeLinkFn = () => {
  const { isRelationship } = useSchema();
  const computeLink = (node: ComputeLinkNode): string | undefined => {
    let redirectLink: string | undefined;
    // Special case of Sightings.
    if (node.relationship_type === 'stix-sighting-relationship') {
      if (node.to) {
        redirectLink = `${resolveLink(node.to.entity_type)}/${node.to.id}/knowledge/sightings/${node.id}`;
      } else if (node.from) {
        redirectLink = `${resolveLink(node.from.entity_type)}/${node.from.id}/knowledge/sightings/${node.id}`;
      } else {
        redirectLink = undefined;
      }
    } else if (node.relationship_type) {
      if (
        node.from
        && node.from.entity_type
        && !isRelationship(node.from.entity_type)
        && node.from.entity_type !== 'Security-Coverage-Result'
      ) {
        // 'from' not restricted and not a relationship and not SCR
        redirectLink = `${resolveLink(node.from.entity_type)}/${node.from.id}/knowledge/relations/${node.id}`;
      } else if (
        node.to
        && node.to.entity_type
        && !isRelationship(node.to.entity_type)
      ) {
        // if 'from' is restricted or a relationship, redirect to the knowledge relationship tab of 'to'
        redirectLink = `${resolveLink(node.to.entity_type)}/${node.to.id}/knowledge/relations/${node.id}`;
      } else {
        redirectLink = undefined; // no redirection if from and to are restricted
      }
    // Special case of Workspaces (investigations and dashboards).
    } else if (node.entity_type === 'Workspace') {
      redirectLink = `${resolveLink(node.type)}/${node.id}`;
    // Special case of Security coverage results.
    } else if (node.entity_type === 'Security-Coverage-Result') {
      redirectLink = `${resolveLink(node.entity_type)}/${node.resultOf?.id}/result`;
    // Default link of entities.
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
