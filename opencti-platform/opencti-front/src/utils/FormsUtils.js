/**
 * Utility function to check if forms are available for a specific entity type
 * @param {Array} formsEdges - The forms.edges array from GraphQL query
 * @param {String} entityType - The entity type to check for (e.g., 'Report', 'Course-Of-Action')
 * @returns {Boolean} - True if there are active forms for this entity type
 */
export const hasAvailableFormsForEntity = (formsEdges, entityType) => {
  if (!formsEdges || !Array.isArray(formsEdges)) {
    return false;
  }
  
  return formsEdges.some((edge) => {
    if (!edge.node || !edge.node.active) return false;
    
    try {
      const schema = JSON.parse(edge.node.form_schema);
      const formEntityType = schema.mainEntityType || '';
      // Check both formats (with hyphen and underscore)
      const normalizedFormType = formEntityType.toLowerCase().replace(/_/g, '-');
      const normalizedEntityType = entityType.toLowerCase().replace(/_/g, '-');
      
      return normalizedFormType === normalizedEntityType;
    } catch {
      return false;
    }
  });
};
