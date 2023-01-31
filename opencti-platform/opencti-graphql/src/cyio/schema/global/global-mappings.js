export const globalSingularizeSchema = {
  singularizeVariables: {
    '': false, // so there is an object as the root instead of an array
    id: true,
    iri: true,
    object_type: true,
    entity_type: true,
    created: true,
    modified: true,
    // Common
    description: true,
    name: true,
    url: true,
    // Global
    abstract: true,
    address_type: true,
    administrative_area: true,
    city: true,
    color: true,
    content: true,
    country: true,
    country_code: true,
    label_text: true,
    media_type: true,
    phone_number: true,
    postal_code: true,
    reference_purpose: true,
    source_name: true,
    street_address: true,
    usage_type: true,
  },
};
