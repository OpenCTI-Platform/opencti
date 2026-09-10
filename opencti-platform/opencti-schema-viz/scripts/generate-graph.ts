import { fileURLToPath } from 'url';
import { dirname } from 'path';
import { createRequire } from 'module';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const require = createRequire(import.meta.url);

const fs = require('node:fs');
const path = require('node:path');

// 1. Resolve Output Dir (before changing CWD)
const outputDir = path.resolve(__dirname, '../public');

// 2. Switch CWD to opencti-graphql to ensure backend config loading works
const graphqlDir = path.resolve(__dirname, '../../opencti-graphql');
console.log(`Switching CWD to ${graphqlDir} for backend compatibility...`);
process.chdir(graphqlDir);
process.env.INIT_CWD = graphqlDir; // Force config loader to use this dir even if started via yarn

// Fix for .graphql file imports in ts-node
require.extensions['.graphql'] = (module, filename) => {
    module.exports = fs.readFileSync(filename, 'utf8');
};

// Register TS node if not already (auto-handled by running via ts-node, but good reference)
// Register TS node if not already (auto-handled by running via ts-node, but good reference)
require('../../opencti-graphql/src/modules/index'); // Trigger registration

const { schemaAttributesDefinition } = require('../../opencti-graphql/src/schema/schema-attributes');
const { schemaRelationsRefDefinition } = require('../../opencti-graphql/src/schema/schema-relationsRef');
import type { RefAttribute } from '../../opencti-graphql/src/schema/attribute-definition';

const { stixCoreRelationshipsMapping } = require('../../opencti-graphql/src/database/stix');
const { getParentTypes } = require('../../opencti-graphql/src/schema/schemaUtils');
// stixCoreRelationship might be default export or named? checking usage in previous file
// import { isStixCoreRelationship } from ...
require('../../opencti-graphql/src/schema/stixCoreRelationship');

// Ensure directory exists (outputDir is absolute)
if (!fs.existsSync(outputDir)) {
    fs.mkdirSync(outputDir, { recursive: true });
}

const schemaData = {
    nodes: [],
    edges: [],
};

const types = schemaAttributesDefinition.getRegisteredTypes();
const typesSet = new Set(types); // Fast lookup

console.log(`Found ${types.length} registered types.`);

const { execSync } = require('node:child_process');

// ... imports ...

const STIX_SCHEMAS_ROOT = path.join(__dirname, 'stix-schemas');
const STIX_SCHEMAS_PATH = path.join(STIX_SCHEMAS_ROOT, 'schemas');
const COMMON_PATH = path.join(STIX_SCHEMAS_PATH, 'common');
const SDO_PATH = path.join(STIX_SCHEMAS_PATH, 'sdos');
const SRO_PATH = path.join(STIX_SCHEMAS_PATH, 'sros');

const ensureSchemas = () => {
    if (!fs.existsSync(STIX_SCHEMAS_ROOT)) {
        console.log('STIX schemas not found. Downloading from official repository...');
        try {
            execSync('git clone https://github.com/oasis-open/cti-stix2-json-schemas.git ' + STIX_SCHEMAS_ROOT, { stdio: 'inherit' });
            console.log('Schemas downloaded successfully.');
        } catch {
            console.error('FAILED to download schemas. Ensure git is installed and internet is available.');
            process.exit(1);
        }
    } else {
        console.log('STIX schemas found locally.');
    }
};

ensureSchemas();

// Load Core Properties (Base for all)

// Load Core Properties (Base for all)
const BASE_STIX_PROPS = new Set();
try {
    const coreSchema = JSON.parse(fs.readFileSync(path.join(COMMON_PATH, 'core.json'), 'utf8'));
    if (coreSchema.properties) {
        Object.keys(coreSchema.properties).forEach(k => BASE_STIX_PROPS.add(k));
    }
} catch {
    console.warn('WARNING: Failed to load common/core.json schema');
}

// Map OpenCTI Types to STIX Filenames
const getStixFilename = (type: string) => {
    if (type === 'stix-core-relationship') return { path: SRO_PATH, file: 'relationship.json' };

    // Custom Mappings
    const mapping = {
        'Attack-Pattern': 'attack-pattern.json',
        'Intrusion-Set': 'intrusion-set.json',
        'Malware-Analysis': 'malware-analysis.json',
        'Threat-Actor-Group': 'threat-actor.json', // Approximation
        'Threat-Actor-Individual': 'threat-actor.json', // Approximation
        'Course-Of-Action': 'course-of-action.json',
        'Observed-Data': 'observed-data.json',
        'Report': 'report.json',
        'Grouping': 'grouping.json',
        'Note': 'note.json',
        'Opinion': 'opinion.json',
        'Identity': 'identity.json',
        'Indicator': 'indicator.json',
        'Infrastructure': 'infrastructure.json',
        'Campaign': 'campaign.json',
        'Location': 'location.json',
        'Malware': 'malware.json',
        'Tool': 'tool.json',
        'Vulnerability': 'vulnerability.json',
        'Incident': 'incident.json',
    };

    if (mapping[type]) return { path: SDO_PATH, file: mapping[type] };

    // Default kebab conversion attempt
    const kebab = type.replace(/([a-z0-9]|(?=[A-Z]))([A-Z])/g, '$1-$2').toLowerCase();
    return { path: SDO_PATH, file: `${kebab}.json` };
};

const getValidStixProps = (type: string) => {
    const validProps = new Set(BASE_STIX_PROPS);

    // Handle Relationships Generic Type
    // If type is a specific relationship name (e.g. 'uses'), it's an SRO instance, so valid props are relationship props.
    const isRelation = schemaAttributesDefinition.getAttributes(type)?.has('relationship_type');

    // Resolve Filename
    let schemaInfo = null;

    if (type === 'stix-sighting-relationship' || type === 'sighting') {
        schemaInfo = { path: SRO_PATH, file: 'sighting.json' };
    } else if (isRelation || type === 'stix-core-relationship') {
        schemaInfo = { path: SRO_PATH, file: 'relationship.json' };
    } else {
        schemaInfo = getStixFilename(type);
    }

    if (schemaInfo && fs.existsSync(path.join(schemaInfo.path, schemaInfo.file))) {
        try {
            const schema = JSON.parse(fs.readFileSync(path.join(schemaInfo.path, schemaInfo.file), 'utf8'));

            // Check 'properties' directly
            if (schema.properties) {
                Object.keys(schema.properties).forEach(k => validProps.add(k));
            }

            // Check 'allOf' (common pattern in these schemas)
            if (schema.allOf) {
                schema.allOf.forEach((part: { properties?: Record<string, unknown> }) => {
                    if (part.properties) {
                        Object.keys(part.properties).forEach(k => validProps.add(k));
                    }
                });
            }
        } catch {
            // Ignore parse errors
        }
    }

    return validProps;
};

// Helper to get attributes
const getAttributesForType = (type: string) => {
    const attributesMap = schemaAttributesDefinition.getAttributes(type);

    // Get Valid STIX Props for this type from Schema
    const validStixProps = getValidStixProps(type);

    const attributes = [];
    if (attributesMap) {
        attributesMap.forEach((def, name) => {
            // Strict Check: Must be in the official schema properties list
            const isStix = validStixProps.has(name);

            attributes.push({
                name: name,
                type: def.type,
                format: def.format,
                label: def.label,
                multiple: def.multiple,
                mandatory: def.mandatoryType,
                description: def.description,
                isStix: isStix,
            });
        });
    }
    return attributes;
};

// 1. Generate Entity Nodes & Inheritance Edges
types.forEach((type: string) => {
    const attributes = getAttributesForType(type);
    if (attributes.length === 0) {
        // console.warn(`WARNING: No attributes found for entity ${type}`);
    }

    const attributesMap = schemaAttributesDefinition.getAttributes(type);
    let isRel = false;

    if (attributesMap && attributesMap.has('relationship_type')) {
        isRel = true;
    }

    schemaData.nodes.push({
        id: type,
        type: isRel ? 'relationship' : 'entity', // Blue (Entity) or Pink (Relationship)
        data: {
            label: type,
            isRelationship: isRel,
            attributes: attributes,
        },
    });

    // Inheritance Logic
    try {
        const parents = getParentTypes(type);
        let parentFound = null;
        for (let i = parents.length - 1; i >= 0; i--) {
            const p = parents[i];
            if (p !== type && typesSet.has(p)) {
                parentFound = p;
                break;
            }
        }

        if (parentFound) {
            schemaData.edges.push({
                id: `inheritance_${type}_${parentFound}`,
                source: type,
                target: parentFound,
                label: 'is-a',
                type: 'default', // standard edge
                style: { strokeDasharray: '5,5', stroke: '#94a3b8' }, // dashed style
                animated: true
            });
        }
    } catch {
        // Ignore errors for types without explicit hierarchy definitions
    }


});

console.log('Entities extracted. Processing relationships...');

// Helper to check if a type is a Relationship
const isTypeRelationship = (type: string) => {
    const attributesMap = schemaAttributesDefinition.getAttributes(type);
    return attributesMap && attributesMap.has('relationship_type');
};

// 2. Generate Relationship Nodes and Edges from Mapping
const relationshipAggregator = new Map();

Object.entries(stixCoreRelationshipsMapping).forEach(([key, relations]) => {
    const parts = key.split('_');
    const fromType = parts[0];
    const toType = parts[1];

    // Check if target is relationship to decide grouping
    const targetIsExampleRel = isTypeRelationship(toType);

    relations.forEach((rel: { name: string; type: string }) => {
        // Unique ID for the Connection Node (Source + RelName)
        const relNodeId = `${fromType}_${rel.name}`;

        if (!relationshipAggregator.has(relNodeId)) {
            relationshipAggregator.set(relNodeId, {
                id: relNodeId,
                fromType: fromType,
                name: rel.name,
                stixType: rel.type,
                relTargets: [],     // List of Pink Nodes to link directly
                entityTargets: []   // List of Blue Nodes to group
            });
        }

        const agg = relationshipAggregator.get(relNodeId);

        if (targetIsExampleRel) {
            if (!agg.relTargets.includes(toType)) {
                agg.relTargets.push(toType);
            }
        } else {
            if (!agg.entityTargets.includes(toType)) {
                agg.entityTargets.push(toType);
            }
        }
    });
});


// 2b. Inject Node Relationships (Ref Attributes) into Aggregator
const registeredTypes = schemaAttributesDefinition.getRegisteredTypes();
registeredTypes.forEach((type: string) => {
    try {
        const refs = schemaRelationsRefDefinition.getRelationsRef(type);
        refs.forEach((ref: RefAttribute) => {
            if (ref.toTypes && ref.toTypes.length > 0) {
                const relNodeId = `${type}_${ref.name}`;

                if (!relationshipAggregator.has(relNodeId)) {
                    relationshipAggregator.set(relNodeId, {
                        id: relNodeId,
                        fromType: type,
                        name: ref.name,
                        stixType: ref.name,
                        relTargets: [],
                        entityTargets: [],
                        isRefAttribute: true // Flag for Orange styling
                    });
                }
                const agg = relationshipAggregator.get(relNodeId);

                ref.toTypes.forEach((targetType) => {
                    const targetIsRel = isTypeRelationship(targetType);
                    if (targetIsRel) {
                        if (!agg.relTargets.includes(targetType)) {
                            agg.relTargets.push(targetType);
                        }
                    } else {
                        if (!agg.entityTargets.includes(targetType)) {
                            agg.entityTargets.push(targetType);
                        }
                    }
                });
            }
        });
    } catch {
        // Ignore errors
    }
});

let relCount = 0;

// Process Aggregated Relationships
relationshipAggregator.forEach((agg: {
    name: string;
    id: string;
    fromType: string;
    stixType: string;
    relTargets: string[];
    entityTargets: string[],
    isRefAttribute?: boolean
}) => {
    // 1. Create the Relationship Node (Pink)
    let relAttributes: unknown[] = [];

    if (!agg.isRefAttribute) {
        relAttributes = getAttributesForType(agg.name);
        if (relAttributes.length === 0) {
            // Fallback to generic if specific not found (though it should be)
            relAttributes = getAttributesForType('stix-core-relationship');
        }

        if (relAttributes.length === 0) {
            console.warn(`WARNING: No attributes found for relationship ${agg.name} (ID: ${agg.id})`);
        }
    }

    schemaData.nodes.push({
        id: agg.id,
        type: 'relationship',
        data: {
            label: agg.name,
            isRelationship: true,
            stixType: agg.stixType,
            attributes: relAttributes,
            isRefAttribute: agg.isRefAttribute,
        }
    });

    // Edge: Source -> RelNode
    schemaData.edges.push({
        id: `edge_${agg.fromType}_${agg.id}`,
        source: agg.fromType,
        target: agg.id,
        label: '',
    });

    // 2. Handle Targets (Entities AND Relationships grouped together)
    const allTargets = [
        ...agg.entityTargets.map((t: string) => ({ label: t, isRelationship: false })),
        ...agg.relTargets.map((t: string) => ({ label: t, isRelationship: true }))
    ];

    if (allTargets.length > 0) {
        // Sort alphabetically
        allTargets.sort((a, b) => a.label.localeCompare(b.label));

        // Create a SINGLE Target Group Node
        const groupId = `${agg.id}_targets`;

        schemaData.nodes.push({
            id: groupId,
            type: 'target-group',
            data: {
                label: 'Targets',
                items: allTargets,
                isDuplicate: true
            }
        });

        // Single Arrow: RelNode -> GroupNode
        schemaData.edges.push({
            id: `edge_${agg.id}_${groupId}`,
            source: agg.id,
            target: groupId,
            label: '',
        });
    }

    relCount++;
});

console.log(`Generated ${relCount} relationship path nodes.`);

const outputPath = path.join(outputDir, 'schema.json');
fs.writeFileSync(outputPath, JSON.stringify(schemaData, null, 2));
console.log('Schema exported to ' + outputPath);
