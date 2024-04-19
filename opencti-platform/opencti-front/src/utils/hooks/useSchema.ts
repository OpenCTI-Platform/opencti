import { useEffect, useState } from 'react';
import { Option } from '@components/common/form/ReferenceField';
import useAuth from './useAuth';

export interface AvailableEntityOption extends Option {
  type: string;
  id: string;
}

const useSchema = () => {
  const { schema } = useAuth();

  const relationshipsNames = schema.scrs.map(({ label }) => label);

  const isRelationship = (entityType: string) => {
    return relationshipsNames.includes(entityType.toLowerCase());
  };

  const [availableEntityTypes, setAvailableEntityTypes] = useState<AvailableEntityOption[]>([]);

  useEffect(() => {
    const { sdos, scos, smos } = schema;
    const entityTypes = sdos
      .map((sdo) => ({
        ...sdo,
        value: sdo.id,
        type: 'entity_Stix-Domain-Objects',
      }))
      .concat(
        scos.map((sco) => ({
          ...sco,
          value: sco.id,
          type: 'entity_Stix-Cyber-Observables',
        })),
      )
      .concat(
        smos.map((smo) => ({
          ...smo,
          value: smo.id,
          type: 'entity_Stix-Meta-Objects',
        })),
      );
    setAvailableEntityTypes(entityTypes);
  }, [schema]);

  return {
    availableEntityTypes,
    isRelationship,
    schema,
  };
};

export default useSchema;
