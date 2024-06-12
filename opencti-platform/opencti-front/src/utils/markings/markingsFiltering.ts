export type MarkingDefinition = {
  label: string;
  value: string;
  color: string;
  definition_type: string;
  x_opencti_order: number;
  entity: {
    id: string;
    entity_type: string;
    standard_id: string;
    definition_type: string;
    definition: string;
    x_opencti_color: string;
    x_opencti_order: number;
  };
};
export function filterMarkingsOutFor(selectedOptions: MarkingDefinition[], markingsOptions: MarkingDefinition[]) {
  return markingsOptions.filter(
    ({ entity }) => selectedOptions.some((selectedOption) => entity.definition_type === selectedOption.entity.definition_type
        && entity.x_opencti_order <= selectedOption.entity.x_opencti_order)
      || selectedOptions.every((selectedOption) => selectedOption.entity.definition_type !== entity.definition_type),
  );
}

export const checkIsMarkingAllowed = (
  marking: { readonly x_opencti_order: number, readonly definition_type: string | null | undefined },
  allowedMarkings: { readonly x_opencti_order: number, readonly definition_type: string | null | undefined }[],
) => {
  return allowedMarkings.some((m) => m.definition_type === marking.definition_type && m.x_opencti_order >= marking.x_opencti_order);
};
