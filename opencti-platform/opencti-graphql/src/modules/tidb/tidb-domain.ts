import {drizzle} from 'drizzle-orm/mysql2';
import mysql, {type Connection} from 'mysql2/promise';
import {entity, identifier, intrusionSet, malware, relationship, stub} from '../../schema';
import {and, asc, eq, exists, getTableColumns, inArray, or, sql} from 'drizzle-orm';
import {getInputIds, MARKING_TLP_CLEAR, MARKING_TLP_GREEN, MARKING_TLP_RED} from '../../schema/identifier';
import type {MySql2Database} from 'drizzle-orm/mysql2/driver';
import type {LabelAddInput, MalwareAddInput, MarkingDefinitionAddInput} from '../../generated/graphql';
import {ENTITY_TYPE_MALWARE} from '../../schema/stixDomainObject';
import {getParentTypes, isInternalId, isStixId} from '../../schema/schemaUtils';
import {RELATION_OBJECT_LABEL, RELATION_OBJECT_MARKING, RELATION_SAMPLE} from '../../schema/stixRefRelationship';
import {ENTITY_TYPE_LABEL, ENTITY_TYPE_MARKING_DEFINITION} from '../../schema/stixMetaObject';
import {alias} from 'drizzle-orm/mysql-core';
import {idLabel} from '../../schema/schema-labels';
import {doYield} from '../../utils/eventloop-utils';
import {schemaTypesDefinition} from '../../schema/schema-types';
import {ABSTRACT_STIX_REF_RELATIONSHIP} from '../../schema/general';

type NewEntityCommon = typeof entity.$inferInsert;
type NewIdentifier = typeof identifier.$inferInsert;
type NewRelationshipCommon = typeof relationship.$inferInsert;

interface SqlHandler {
    table: any
    type: string
    ids: () => string[]
    representative: () => string
    convert: () => any
    targetRefs: () => {type: string, id: string}[]
}

const tableDefinitions = [
    {
        type: 'malware',
        table: malware,
        relation: 'relationship_malware',
        relation_alias: alias(malware, 'relationship_malware')
    },
    {
        type: 'intrusion-set',
        table: intrusionSet,
        relation: 'relationship_intrusion-set',
        relation_alias: alias(intrusionSet, 'relationship_intrusion-set')
    }
];

const prepareRef = (refs: string[], type: string, transform?: (s: string) => string) => {
    return (refs || []).filter((s) => s !== null).map((s) => ({type , id: transform ? transform(s) : s }));
};

const handleMalware = (input: MalwareAddInput): SqlHandler => {
    type NewMalware = typeof malware.$inferInsert;
    return {
        table: malware,
        ids: () => getInputIds(ENTITY_TYPE_MALWARE, { entity_type: ENTITY_TYPE_MALWARE, ...input }),
        type: ENTITY_TYPE_MALWARE,
        targetRefs: () => {
            const samples = prepareRef(input.samples as string[], RELATION_SAMPLE);
            const markings = prepareRef(input.objectMarking as string[], RELATION_OBJECT_MARKING);
            const labels = prepareRef(input.objectLabel as string[], RELATION_OBJECT_LABEL, idLabel);
            return [...samples, ...markings, ...labels];
        },
        representative: () => input.name,
        convert: () => {
            const newMalware: NewMalware = {
                name: input.name
            };
            return newMalware;
        }
    };
};
const handleMarking = (input: MarkingDefinitionAddInput): SqlHandler => {
    type NewStub = typeof stub.$inferInsert;
    return {
        table: stub,
        ids: () => getInputIds(ENTITY_TYPE_MARKING_DEFINITION, { entity_type: ENTITY_TYPE_MARKING_DEFINITION, ...input }),
        type: ENTITY_TYPE_MARKING_DEFINITION,
        targetRefs: () => [], // No refs available for marking definition
        representative: () => input.definition,
        convert: () => {
            const newStub: NewStub = {
                name: input.definition,
                color: input.x_opencti_color ?? '#ffffff',
                category: input.definition_type,
                order: input.x_opencti_order ?? 0
            };
            return newStub;
        }
    };
};
const handleLabel = (input: LabelAddInput): SqlHandler => {
    type NewStub = typeof stub.$inferInsert;
    return {
        table: stub,
        ids: () => getInputIds(ENTITY_TYPE_LABEL, { entity_type: ENTITY_TYPE_LABEL, ...input }),
        type: ENTITY_TYPE_LABEL,
        targetRefs: () => [], // No refs available for label
        representative: () => input.value,
        convert: () => {
            const newStub: NewStub = {
                name: input.value,
                color: input.color ?? '#ffffff',
                category: 'label',
                order: 0
            };
            return newStub;
        }
    };
};

const createEntity = async (db: MySql2Database & { $client: Connection }, handler: SqlHandler) => {
    const start = new Date().getTime();
    // Resolve dependencies
    const targetRefs = handler.targetRefs().map((r) => r.id);
    const startFind = new Date().getTime();
    const refEntities = targetRefs.length > 0 ? await db.select().from(entity)
        .rightJoin(identifier, eq(entity.id, identifier.targetId))
        .where(
            or(
                inArray(entity.id, targetRefs.filter((r) => isInternalId(r)).map((r) => BigInt(r))),
                inArray(identifier.identifier, targetRefs.filter((r) => isStixId(r))),
            )
        ) : [];
    console.log('Time to resolve refs ' + (new Date().getTime() - startFind) + ' ms ');
    // console.log('refEntities', targetRefs, refEntities);
    const refEntitiesMap = new Map<string, {  id: bigint, table: string }>();
    for (const refEntity of refEntities) {
        if (refEntity.identifier && refEntity.entity) {
            const id = refEntity.identifier.identifier;
            if (id) {
                refEntitiesMap.set(id, {id: refEntity.entity.id, table: refEntity.entity.targetTable});
            }
        } else if(refEntity.entity) {
            const id = refEntity.entity.id;
            refEntitiesMap.set(id.toString(), { id: refEntity.entity.id, table: refEntity.entity.targetTable });
        }
    }
    // Create entity
    const startCreate = new Date().getTime();
    await db.transaction(async (tx) => {
        // 01 - First check if instance already exists through any identifiers we know about
        const ids = handler.ids();
        const [existingEntity] = await tx.select({ id: entity.id }).from(entity)
            .rightJoin(identifier, eq(entity.id, identifier.targetId))
            .where(inArray(identifier.identifier, ids));

        let existingSpecificId;
        if (existingEntity) {
            // Existing element, need to update it
            // upsert common if needed
            // upsert entity
            // Add missing identifiers
            console.log('Existing entity', existingEntity.id);
            // noinspection JSUnusedAssignment
            existingSpecificId = existingEntity.id;
        } else {
            console.log('Creating entity');
            // New element, need to create it
            // If it fails, rollback the whole transaction.
            // Fail can be due to race condition in entity creation
            // Specific
            const [specificResult] = await tx.insert(handler.table).values(handler.convert()).$returningId();
            existingSpecificId = specificResult.id;
            // Common
            const newCommon: NewEntityCommon = {
                entity_type: handler.type.toLowerCase(),
                parent_types: getParentTypes(handler.type),
                representative_main: handler.representative(),
                targetId: existingSpecificId,
                targetTable: handler.table[Symbol.for('drizzle:Name')],
            };
            const [newEntity] : any[] = await tx.insert(entity).values(newCommon).$returningId();
            const entityId = newEntity.id;
            // Identifiers
            const identifiers: NewIdentifier[] = ids.map((id) => ({
                identifier: id,
                type: isStixId(id) ? 'stix': 'internal',
                targetId: entityId,
                targetTable: 'entity',
            } as NewIdentifier));
            // If it fails, rollback the whole transaction.
            // Nothing will created if identifiers are not fully created
            await tx.insert(identifier).values(identifiers);
            // Create refs relationships
            const rels = handler.targetRefs().filter((r) => refEntitiesMap.has(r.id));
            const relationships: NewRelationshipCommon[] = [];
            for (let index = 0; index < rels.length; index++) {
                const rel = rels[index];
                const idFromMap = refEntitiesMap.get(rel.id);
                if (idFromMap) {
                    relationships.push({
                        relationship_type: rel.type,
                        parent_types: getParentTypes(rel.type),
                        fromId: entityId,
                        fromTable: 'entity', // Ref can only exists between entities
                        toId: idFromMap.id,
                        toTable: 'entity', // Ref can only exists between entities
                    });
                }
            }
            if (relationships.length > 0) {
                await tx.insert(relationship).values(relationships);
            }
        }
    });
    console.log('Time to find + create ' + (new Date().getTime() - startCreate) + ' ms ');
    console.log('Time to complete ' + (new Date().getTime() - start) + ' ms ');
};

export const initStubs = async (_context: any, __userContext: any) => {
    const connection = await mysql.createConnection({ uri: 'mysql://root@127.0.0.1:4000/opencti' });
    const db = drizzle(connection);
    // region Markings
    const white: MarkingDefinitionAddInput = { definition: 'TLP:WHITE', definition_type: 'TLP', stix_id: MARKING_TLP_CLEAR, x_opencti_order: 0 };
    const green: MarkingDefinitionAddInput = { definition: 'TLP:GREEN', definition_type: 'TLP', stix_id: MARKING_TLP_GREEN, x_opencti_order: 1 };
    const red: MarkingDefinitionAddInput = { definition: 'TLP:RED', definition_type: 'TLP', stix_id: MARKING_TLP_RED, x_opencti_order: 2 };
    await createEntity(db, handleMarking(white));
    await createEntity(db, handleMarking(green));
    await createEntity(db, handleMarking(red));
    // endregion
    // region Labels
    const filigranLabel: LabelAddInput = { value: 'FILIGRAN' };
    await createEntity(db, handleLabel(filigranLabel));
    const fbiLabel: LabelAddInput = { value: 'FBI' };
    await createEntity(db, handleLabel(fbiLabel));
    // endregion
    return true;
};

export const initSchema = async (_context: any, __userContext: any) => {

    const connection = await mysql.createConnection({ uri: 'mysql://root@127.0.0.1:4000/opencti' });
    const db = drizzle(connection);

    const malwareToCreate1: MalwareAddInput = {
        name: 'test-source1',
        description: 'test-source1',
        stix_id: 'malware--b7ea80a5-a56c-4443-854d-1a4eb3df9d2b'
    };
    await createEntity(db, handleMalware(malwareToCreate1));

    const malwareToCreate2: MalwareAddInput = {
        name: 'test-source2',
        description: 'test-source2',
        stix_id: 'malware--b7ea80a5-a56c-4443-854d-1a4eb3df9d3b'
    };
    await createEntity(db, handleMalware(malwareToCreate2));

    const malwareToCreate3: MalwareAddInput = {
      name: 'test',
      description: 'test',
      stix_id: 'malware--e454d6f5-2532-4bb9-9758-639991d6ba03',
      objectMarking: [MARKING_TLP_GREEN],
      objectLabel: ['FILIGRAN', 'FBI'],
      x_opencti_stix_ids: ['malware--d06563e6-e227-48e2-9912-58e264a12016'],
      samples: ['malware--b7ea80a5-a56c-4443-854d-1a4eb3df9d2b', 'malware--b7ea80a5-a56c-4443-854d-1a4eb3df9d3b'],
    };
    await createEntity(db, handleMalware(malwareToCreate3));

    return true;
};

export const queries = async (_context: any, __userContext: any) => {
    const connection = await mysql.createConnection({ uri: 'mysql://root@127.0.0.1:4000/opencti' });
    const db = drizzle(connection);
    const start = new Date().getTime();

    // Testing filter
    const includeRefs = 'base'; // base or extended
    const filterTypes = ['malware'];
    const includeInRegardsOfFilter = false;
    const findIds = ['malware--e454d6f5-2532-4bb9-9758-639991d6ba03'];

    // Builder
    const relationship_entity = alias(entity, 'relationship_entity');
    const identifiers = sql<any>`(SELECT JSON_ARRAYAGG(JSON_OBJECT('uuid', ${identifier.identifier},'type', ${identifier.type})) 
        FROM ${identifier} WHERE ${identifier.targetId} = ${entity.id})`;
    const tables: any = {
        entity: getTableColumns(entity),
        identifiers: identifiers,
        relationship: getTableColumns(relationship),
        relationship_entity: getTableColumns(relationship_entity),
    };
    for (let i = 0; i < tableDefinitions.length; i += 1) {
        const table = tableDefinitions[i];
        tables[table.type] = getTableColumns(table.table);
        tables[table.relation] = getTableColumns(table.relation_alias);
    }
    // region base
    const baseQuery = db.select(tables).from(entity);
    for (let baseIndex = 0; baseIndex < tableDefinitions.length; baseIndex += 1) {
        const table = tableDefinitions[baseIndex];
        baseQuery.leftJoin(table.table, and(eq(entity.targetId, table.table.id), eq(entity.targetTable, table.type)));
    }
    // endregion

    // region refs fetching
    const refTypes = includeRefs === 'base' ? [RELATION_OBJECT_MARKING, RELATION_OBJECT_LABEL]
        : schemaTypesDefinition.get(ABSTRACT_STIX_REF_RELATIONSHIP);
    const relationship_stub = alias(stub, 'relationship_stub');
    baseQuery.leftJoin(relationship, and(eq(entity.id, relationship.fromId), inArray(relationship.relationship_type, refTypes)))
        .leftJoin(relationship_entity, and(eq(relationship.toId, relationship_entity.id), eq(relationship.toTable, 'entity')))
            .leftJoin(relationship_stub, and(eq(relationship_entity.targetId, relationship_stub.id), eq(relationship_entity.targetTable, 'stub')));
    for (let leftIndex = 0; leftIndex < tableDefinitions.length; leftIndex += 1) {
        const table = tableDefinitions[leftIndex];
        baseQuery.leftJoin(table.relation_alias, and(eq(relationship_entity.targetId, table.relation_alias.id),
            eq(relationship_entity.targetTable, table.type)));
    }
    // endregion

    // region where
    const filteredQuery = baseQuery
        .where(and(
            // filter on an entity attribute
            filterTypes.length > 0 ? inArray(entity.entity_type, filterTypes) : undefined,
            // Filter on instance ids
            findIds.length > 0 ? exists(
                db.select().from(identifier)
                    .rightJoin(entity, and(eq(identifier.targetId, entity.id)))
                    .where(inArray(identifier.identifier, findIds))
            ) : undefined,
            // Filter in regards of targeting sample with specific name
            includeInRegardsOfFilter ? exists(
                db.select().from(relationship)
                    .leftJoin(relationship_entity, and(eq(relationship.toId, relationship_entity.id), eq(relationship.toTable, 'entity')))
                        .leftJoin(relationship_stub, and(eq(relationship_entity.targetId, relationship_stub.id), eq(relationship_entity.targetTable, 'stub')))
                        //.leftJoin(relationship_malware, and(eq(relationship_entity.targetId, relationship_malware.id), eq(relationship_entity.targetTable, 'malware')))
                    .where(
                        and(
                            eq(relationship.fromId, entity.id),
                            eq(relationship.relationship_type, RELATION_SAMPLE),
                            //eq(relationship_malware.name, 'test-source21'),
                        )
                    )
                ) : undefined
            )
        );
    // endregion

    // region order by and fetch result
    const orderedQuery = filteredQuery
        .orderBy(asc(entity.created_at))
        .limit(100)
        .offset(0);
    // endregion

    // region Execute query
    const res = await orderedQuery;
    // endregion

    console.log('Time to find ' + res.length + ' items ' +  (new Date().getTime() - start) + ' ms ');

    // region rebuild result
    const elements = [];
    const idIndex = new Map<bigint, number>();
    for (let index = 0; index < res.length; index += 1) {
        await doYield();
        const element: any = res[index];
        if (element.entity) {
            const { entityType } = element.entity;
            const existingIndex = idIndex.get(element.entity.id);
            if (existingIndex !== undefined) {
                const baseObject: any = elements[existingIndex];
                if (element.relationship) {
                    const {relationship_type, toTable} = element.relationship;
                    const entityTarget = element[`relationship_${toTable}`];
                    const specificTarget: any = element[`relationship_${entityTarget?.targetTable}`];
                    const item = { ...specificTarget, ...entityTarget, i_relation: element.relationship };
                    if (baseObject[relationship_type]) {
                        baseObject[relationship_type].push(item);
                    } else {
                        baseObject[relationship_type] = [item];
                    }
                }
                elements[existingIndex] = baseObject;
            } else {
                idIndex.set(element.entity.id, index);
                const specific = element[entityType];
                const baseObject: any = { ...specific, ...element.entity, identifiers: element.identifiers };
                if (element.relationship) {
                    const { relationship_type, toTable } = element.relationship;
                    const entityTarget = element[`relationship_${toTable}`];
                    const specificTarget: any = element[`relationship_${entityTarget?.targetTable}`];
                    baseObject[relationship_type] = [{ ...specificTarget, ...entityTarget, i_relation: element.relationship }];
                }
                elements[index] = baseObject;
            }
        }
    }
    // endregion

    console.log('Time to find+rebuild ' + elements.length + ' elements ' + (new Date().getTime() - start) + ' ms ');

    // return
    return true;
};