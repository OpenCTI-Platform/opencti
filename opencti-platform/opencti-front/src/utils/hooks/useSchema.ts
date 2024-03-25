import useAuth from './useAuth';

const useSchema = () => {
  const { schema } = useAuth();

  const relationshipsNames = schema.scrs.map(({ label }) => label);

  const isRelationship = (entityType: string) => {
    return relationshipsNames.includes(entityType.toLowerCase());
  };

  return {
    isRelationship,
    schema,
  };
};

export default useSchema;
