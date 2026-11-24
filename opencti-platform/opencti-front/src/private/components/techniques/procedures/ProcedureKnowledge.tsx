import React from 'react';
import { Navigate, Route, Routes, useLocation } from 'react-router';
import { graphql, useFragment } from 'react-relay';
import { PATH_PROCEDURE } from '@components/common/routes/paths';
import useAuth from '../../../../utils/hooks/useAuth';
import { getRelationshipTypesForEntityType } from '../../../../utils/Relation';
import EntityStixCoreRelationships from '../../common/stix_core_relationships/EntityStixCoreRelationships';
import StixDomainObjectKnowledge from '../../common/stix_domain_objects/StixDomainObjectKnowledge';
import StixCoreRelationship from '../../common/stix_core_relationships/StixCoreRelationship';
import { ProcedureKnowledge_procedure$key } from './__generated__/ProcedureKnowledge_procedure.graphql';

const ProcedureKnowledgeFragment = graphql`
  fragment ProcedureKnowledge_procedure on Procedure {
    id
    name
    entity_type
  }
`;

// Knowledge sections: path, relationship type, target types and whether the procedure is the target.
const sections: { path: string; relationshipType: string; types: string[]; isRelationReversed: boolean }[] = [
  { path: 'attack_patterns', relationshipType: 'implements-technique', types: ['Attack-Pattern'], isRelationReversed: false },
  { path: 'intrusion_sets', relationshipType: 'uses', types: ['Intrusion-Set'], isRelationReversed: true },
  { path: 'threat_actors', relationshipType: 'uses', types: ['Threat-Actor'], isRelationReversed: true },
  { path: 'campaigns', relationshipType: 'uses', types: ['Campaign'], isRelationReversed: true },
  { path: 'malwares', relationshipType: 'uses', types: ['Malware'], isRelationReversed: false },
  { path: 'tools', relationshipType: 'uses', types: ['Tool'], isRelationReversed: false },
  { path: 'vulnerabilities', relationshipType: 'exploits', types: ['Vulnerability'], isRelationReversed: false },
  { path: 'indicators', relationshipType: 'indicates', types: ['Indicator'], isRelationReversed: true },
  { path: 'courses_of_action', relationshipType: 'mitigates', types: ['Course-Of-Action'], isRelationReversed: true },
];

export const PROCEDURE_KNOWLEDGE_SECTIONS = sections.map(({ path }) => path);

interface ProcedureKnowledgeProps {
  procedureData: ProcedureKnowledge_procedure$key;
}

const ProcedureKnowledge = ({ procedureData }: ProcedureKnowledgeProps) => {
  const procedure = useFragment(ProcedureKnowledgeFragment, procedureData);
  const location = useLocation();
  const link = `${PATH_PROCEDURE(procedure.id)}/knowledge`;
  const { schema } = useAuth();
  const allRelationshipsTypes = getRelationshipTypesForEntityType(procedure.entity_type, schema);
  return (
    <div data-testid="procedure-knowledge">
      <Routes>
        <Route path="/relations/:relationId" element={<StixCoreRelationship />} />
        <Route
          path="/overview"
          element={(
            <StixDomainObjectKnowledge
              stixDomainObjectId={procedure.id}
              stixDomainObjectType="Procedure"
            />
          )}
        />
        <Route
          path="/all"
          element={(
            <EntityStixCoreRelationships
              key={location.pathname}
              entityId={procedure.id}
              relationshipTypes={allRelationshipsTypes}
              entityLink={link}
              allDirections={true}
            />
          )}
        />
        <Route
          path="/related"
          element={(
            <EntityStixCoreRelationships
              key={location.pathname}
              entityId={procedure.id}
              relationshipTypes={['related-to']}
              entityLink={link}
              allDirections={true}
            />
          )}
        />
        {sections.map(({ path, relationshipType, types, isRelationReversed }) => (
          <Route
            key={path}
            path={`/${path}`}
            element={(
              <EntityStixCoreRelationships
                key={location.pathname}
                entityId={procedure.id}
                relationshipTypes={[relationshipType]}
                stixCoreObjectTypes={types}
                entityLink={link}
                isRelationReversed={isRelationReversed}
              />
            )}
          />
        ))}
        <Route index element={<Navigate replace={true} to="overview" />} />
      </Routes>
    </div>
  );
};

export default ProcedureKnowledge;
