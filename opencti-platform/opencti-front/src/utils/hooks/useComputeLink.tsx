import React, { ReactNode, createContext, useContext } from 'react';
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

type ComputeLinkFn = ReturnType<typeof useComputeLinkFn>;

const ComputeLinkContext = createContext<ComputeLinkFn | null>(null);

export const useComputeLink = (): ComputeLinkFn => {
  const computeLink = useContext(ComputeLinkContext);
  if (!computeLink) {
    throw new Error('useSafeComputeLink must be used within ComputeLinkProvider');
  }
  return computeLink;
};

const PrivateComputeLinkProvider: React.FC<{ children: ReactNode }> = ({ children }) => {
  const computeLink = useComputeLinkFn();
  return (
    <ComputeLinkContext.Provider value={computeLink as ComputeLinkFn}>
      {children}
    </ComputeLinkContext.Provider>
  );
};

export const ComputeLinkProvider = ({ isPublicRoute, children }: { isPublicRoute: boolean, children: ReactNode }) => {
  if (isPublicRoute) {
    return (
      <ComputeLinkContext.Provider value={() => ''}>
        {children}
      </ComputeLinkContext.Provider>
    );
  }

  return <PrivateComputeLinkProvider>{children}</PrivateComputeLinkProvider>;
};
