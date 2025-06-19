import { JsonMapperRepresentationEdit, JsonMapperRepresentationFormData } from '@components/data/jsonMapper/representations/Representation';

export type JsonMapperEdit = Omit<JsonMapperEditionContainerFragment_jsonMapper$data, ' $fragmentType' | 'errors' | 'representations'> & {
  representations: JsonMapperRepresentationEdit[]
};

export interface JsonMapperFormData {
  id: string
  name?: string
  entity_representations: JsonMapperRepresentationFormData[]
  relationship_representations: JsonMapperRepresentationFormData[]
  errors?: string
}
