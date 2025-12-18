import {int, bigint, boolean, index, json, mysqlTable, text, timestamp, varchar} from 'drizzle-orm/mysql-core';
import {sql} from 'drizzle-orm';

export const users = mysqlTable('user', {
    id: bigint('id', { mode: 'bigint' }).autoincrement().primaryKey(),
    // ident
    email: varchar('user_email', {length: 256}).unique(),
    password: text('password'),
    // meta
    name: varchar('name', {length: 256}),
    description: text('description'),
    firstname: varchar('firstname', {length: 256}),
    lastname: varchar('lastname', {length: 256}),
    // dates
    created_at: timestamp('created_at', { fsp: 6 }).default(sql`CURRENT_TIMESTAMP(6)`),
    modified_at: timestamp('modified_at', { fsp: 6 }).default(sql`CURRENT_TIMESTAMP(6)`),
});

export const identifier = mysqlTable('identifier', {
    id: bigint('id', { mode: 'bigint' }).autoincrement().primaryKey(),
    identifier: varchar('identifier', { length: 255 }).unique(),
    type: varchar('type', { length: 50 }).notNull(), // 'stix', 'alias', ...
    creator_id: bigint('creator_id', { mode: 'bigint' }).references(() => users.id),
    // targets
    targetId: bigint('target_id', { mode: 'bigint' }).notNull(), // id in entity or relationship
    targetTable: varchar('target_table', { length: 50 }).notNull(), // 'entity_common' or 'relationship_common'
    // dates
    created_at: timestamp('created_at', { fsp: 6 }).default(sql`CURRENT_TIMESTAMP(6)`),
    modified_at: timestamp('modified_at', { fsp: 6 }).default(sql`CURRENT_TIMESTAMP(6)`),
}, (table) => {
    return {
        idxReverse: index('idx_ident_reverse').on(table.id),
    };
});

export const entity = mysqlTable('entity', {
    id: bigint('id', { mode: 'bigint' }).autoincrement().primaryKey(),
    entity_type: varchar('entity_type', { length: 50 }).notNull(), // malware
    parent_types: json('parent_types').$type<string[]>().notNull(),
    representative_main: varchar('representative_main', { length: 256 }).notNull(),
    creator_id: bigint('creator_id', { mode: 'bigint' }).references(() => users.id),
    // targets
    targetId: bigint('target_id', { mode: 'bigint' }).notNull(), // Malware ID
    targetTable: varchar('target_table', { length: 50 }).notNull(), // 'malware'
    // dates
    created_at: timestamp('created_at', { fsp: 6 }).default(sql`CURRENT_TIMESTAMP(6)`),
    modified_at: timestamp('modified_at', { fsp: 6 }).default(sql`CURRENT_TIMESTAMP(6)`),
}, (table) => {
    return {
        // This is required for efficient parent type searches
        parentTypesIdx: index('idx_parent_types').on(sql`(CAST(${table.parent_types} AS CHAR(32) ARRAY))`)
    };
});

export const relationship = mysqlTable('relationship', {
    id: bigint('id', { mode: 'bigint' }).autoincrement().primaryKey(),
    relationship_type: varchar('relationship_type', { length: 50 }).notNull(), // malware
    parent_types: json('parent_types').$type<string[]>().notNull(),
    creator_id: bigint('creator_id', { mode: 'bigint' }).references(() => users.id),
    // From
    fromId: bigint('from_id', { mode: 'bigint' }).notNull(),
    fromTable: varchar('from_table', { length: 50 }).notNull(), // 'entity_common' or 'relationship_common'
    // To
    toId: bigint('to_id', { mode: 'bigint' }).notNull(),
    toTable: varchar('to_table', { length: 50 }).notNull(), // 'entity_common' or 'relationship_common'
    // dates
    created_at: timestamp('created_at', { fsp: 6 }).default(sql`CURRENT_TIMESTAMP(6)`),
    modified_at: timestamp('modified_at', { fsp: 6 }).default(sql`CURRENT_TIMESTAMP(6)`),
}, (table) => {
    return {
        // This is required for efficient parent type searches
        parentTypesIdx: index('idx_parent_types').on(sql`(CAST(${table.parent_types} AS CHAR(32) ARRAY))`)
    };
});

export const malware = mysqlTable('malware', {
    id: bigint('id', { mode: 'bigint' }).autoincrement().primaryKey(),
    name: varchar('name', { length: 255 }).notNull(),
    description: text('description'),
    malware_types: json('malware_types').$type<string[]>(),
    implementation_languages: json('implementation_languages').$type<string[]>(),
    architecture_execution_envs: json('architecture_execution_envs').$type<string[]>(),
    capabilities: json('capabilities').$type<string[]>(),
    is_family: boolean('is_family').default(false),
    first_seen: timestamp('first_seen', { fsp: 6 }).default(sql`CURRENT_TIMESTAMP(6)`),
    last_seen: timestamp('last_seen', { fsp: 6 }).default(sql`CURRENT_TIMESTAMP(6)`),
}, (table) => {
    return {
        idxName: index('idx_malware_name').on(table.name),
    };
});

export const intrusionSet = mysqlTable('intrusion-set', {
    id: bigint('id', { mode: 'bigint' }).autoincrement().primaryKey(),
    name: varchar('name', { length: 255 }).notNull(),
    description: text('description'),
    first_seen: timestamp('first_seen', { fsp: 6 }).default(sql`CURRENT_TIMESTAMP(6)`),
    last_seen: timestamp('last_seen', { fsp: 6 }).default(sql`CURRENT_TIMESTAMP(6)`),
}, (table) => {
    return {
        idxName: index('idx_intrusion_set_name').on(table.name),
    };
});

export const stub = mysqlTable('stub', {
    id: bigint('id', { mode: 'bigint' }).autoincrement().primaryKey(),
    name: varchar('name', { length: 255 }).notNull(),
    order: int('order').notNull(),
    color: varchar('color', { length: 255 }).notNull(),
    category: varchar('category', { length: 255 }).notNull(),
}, (table) => {
    return {
        idxName: index('idx_tag_name').on(table.name),
    };
});