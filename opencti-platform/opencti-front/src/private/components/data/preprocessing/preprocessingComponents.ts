export interface PreprocessingComponentDef {
  id: string; name: string; description: string; category: string; icon: string;
  isNew?: boolean; isEntryPoint?: boolean;
  ports?: Array<{ id: string; type: 'in' | 'out' }>;
}
export const LISTEN_INGESTION: PreprocessingComponentDef = {
  id: 'LISTEN_INGESTION', name: 'Listen to ingestion',
  description: 'Triggered when an entity is created during ingestion (scope: create)',
  category: 'Triggers', icon: 'event', isEntryPoint: true, ports: [{ id: 'out', type: 'out' }],
};
export const PREPROCESSING_COMPONENTS: PreprocessingComponentDef[] = [
  { id: 'CHANGE_ENTITY_TYPE',        name: 'Change entity type',          description: 'Change the type of the ingested entity',                    category: 'Transformation Actions', icon: 'transform',     isNew: true, ports: [{ id: 'out', type: 'out' }] },
  { id: 'CONTAINER_WRAPPER',         name: 'Container wrapper',           description: 'Wrap the entity in a container',                             category: 'Transformation Actions', icon: 'package',                  ports: [{ id: 'out', type: 'out' }] },
  { id: 'EXTRACT_OBSERVABLE',        name: 'Extract observable from IOC', description: 'Extract an observable from an indicator of compromise',      category: 'Transformation Actions', icon: 'eye',                      ports: [{ id: 'out', type: 'out' }] },
  { id: 'PROMOTE_IOC',               name: 'Promote IOC from observable', description: 'Promote an observable to an indicator of compromise',        category: 'Transformation Actions', icon: 'trending-up',              ports: [{ id: 'out', type: 'out' }] },
  { id: 'MANIPULATE_KNOWLEDGE',      name: 'Manipulate knowledge',        description: 'Add, modify or delete knowledge attributes',                 category: 'Transformation Actions', icon: 'database-edit',            ports: [{ id: 'out', type: 'out' }] },
  { id: 'MATCH_KNOWLEDGE',           name: 'Match knowledge',             description: 'Match entity against existing knowledge',                    category: 'Transformation Actions', icon: 'magnify',                  ports: [{ id: 'out', type: 'out' }] },
  { id: 'DEDUCT_MAIN_OBS',           name: 'Deduct Main Observable',      description: 'Deduce the main observable from context',                    category: 'Transformation Actions', icon: 'chart-tree',    isNew: true, ports: [{ id: 'out', type: 'out' }] },
  { id: 'MANAGE_ACCESS_RESTRICTION', name: 'Manage access restriction',   description: 'Apply access restriction rules',                             category: 'Share & Access Actions', icon: 'lock',                     ports: [{ id: 'out', type: 'out' }] },
  { id: 'REMOVE_ACCESS_RESTRICTION', name: 'Remove access restriction',   description: 'Remove existing access restrictions',                        category: 'Share & Access Actions', icon: 'lock-open',                ports: [{ id: 'out', type: 'out' }] },
  { id: 'SHARE_TO_ORG',              name: 'Share to organization',       description: 'Share the entity with a specific organization',              category: 'Share & Access Actions', icon: 'domain',                   ports: [{ id: 'out', type: 'out' }] },
  { id: 'UNSHARE_FROM_ORG',          name: 'Unshare from organization',   description: 'Revoke sharing with an organization',                        category: 'Share & Access Actions', icon: 'domain-remove',            ports: [{ id: 'out', type: 'out' }] },
  { id: 'DO_NOT_INGEST',             name: 'Do not ingest',               description: 'Discard the entity — stop processing here',                  category: 'End Actions',            icon: 'cancel',        isNew: true, ports: [] },
  { id: 'SEND_FOR_INGESTION',        name: 'Send for ingestion',          description: 'Forward the entity for standard ingestion',                  category: 'End Actions',            icon: 'check-circle',             ports: [] },
];
export const findComponent = (id: string): PreprocessingComponentDef | undefined =>
  [LISTEN_INGESTION, ...PREPROCESSING_COMPONENTS].find((c) => c.id === id);
