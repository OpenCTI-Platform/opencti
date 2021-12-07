import {v4 as uuid4, v5 as uuid5} from "uuid";
import {OASIS_SCO_NS} from "../utils"

export const insertPortsQuery = (ports) => {
    let iris = [];
    let graphs = []
    ports.forEach((port) => {
        const id = uuid4();
        const insertPredicates = [];
        const iri = `<http://scap.nist.gov/ns/asset-identification#Port-${id}>`;
        iris.push(iri);
        insertPredicates.push(`${iri} a <http://darklight.ai/ns/common#ComplexDatatype>`);
        insertPredicates.push(`${iri} a <http://scap.nist.gov/ns/asset-identification#Port>`);
        insertPredicates.push(`${iri} <http://darklight.ai/ns/common#id> "${id}"`)
        if(port.protocols !== undefined) {
            port.protocols.forEach((protocol) => insertPredicates.push(`${iri} <http://scap.nist.gov/ns/asset-identification#protocols> "${protocol}"`));
        }
        insertPredicates.push(`${iri} <http://scap.nist.gov/ns/asset-identification#port_number> ${port.port_number}`)
        const combinedPredicates = insertPredicates.join(" .\n      ");
        graphs.push(`
    GRAPH ${iri} {
        ${combinedPredicates}
    }
        `)
    })
    const query = `
INSERT DATA {
    ${graphs.join("\n")}
}
    `;
    return {iris, query};
}

export const insertPortRelationships = (parentIri, portsIris) => {
    const predicates = portsIris
        .map((port) => `${parentIri} <http://scap.nist.gov/ns/asset-identification#ports> ${port}`)
        .join(" .\n        ")
    return `
INSERT DATA {
    GRAPH ${parentIri} {
        ${predicates}
    }
}
    `
}

/**
 * @param ip - the ip string
 * @param version - either 4 or 6 (number values)
 */
export const insertIPQuery = (ip, version) => {
    const graphs = [], ipIris = []
    const timestamp = new Date().toISOString();
    ip.forEach((ip) => {
        const insertPredicates = []
        const idMaterial = {ip};
        const id = uuid5(JSON.stringify(idMaterial), OASIS_SCO_NS);
        let type, rdfType, iri;
        if(version === 4){
            type = "ipv4-addr";
            iri = `<http://scap.nist.gov/ns/asset-identification#IpV4Address-${id}>`;
            rdfType = "<http://scap.nist.gov/ns/asset-identification#IpV4Address>";
        } else if (version === 6){
            type = "ipv6-addr";
            iri = `<http://scap.nist.gov/ns/asset-identification#IpV6Address-${id}>`;
            rdfType = "<http://scap.nist.gov/ns/asset-identification#IpV6Address>";
        } else {
            throw new Error(`Invalid IP address version: ${version}`);
        }
        ipIris.push(iri);
        insertPredicates.push(`${iri} a ${rdfType}`);
        insertPredicates.push(`${iri} a <http://scap.nist.gov/ns/asset-identification#IpAddress>`);
        insertPredicates.push(`${iri} <http://darklight.ai/ns/common#id> "${id}"`);
        insertPredicates.push(`${iri} <http://scap.nist.gov/ns/asset-identification#ip_address_value> "${ip.ip_address_value}"`)
        insertPredicates.push(`${iri} <http://darklight.ai/ns/common#object_type> "${type}"`);
        insertPredicates.push(`${iri} <http://darklight.ai/ns/common#created> "${timestamp}"^^xsd:dateTime`);
        insertPredicates.push(`${iri} <http://darklight.ai/ns/common#modified> "${timestamp}"^^xsd:dateTime`);
        graphs.push(`
    GRAPH ${iri} {
        ${insertPredicates.join(".\n        ")}
    }    
        `)
    })
    const query = `
INSERT DATA {
    ${graphs.join("\n    ")}
}
    `;
    return {ipIris, query};
}

/**
 * @param parentIri - the object of the relationship. (THIS ASSUMES GRAPHS)
 * @param ipIri - iri of the existing IP object
 */
export const insertIPRelationship = (parentIri, ipIris) => {
    const predicates = ipIris
        .map((ipIri) => `${parentIri} <http://scap.nist.gov/ns/asset-identification#ip_address> ${ipIri}`)
        .join(".\n        ")
    return `
INSERT DATA {
    GRAPH ${parentIri} {
        ${predicates}
    }
}
    `
}

export const deletePortQuery = (iri) => {
    return `
    DELETE {
        GRAPH <${iri}> {
            <${iri}> ?p ?o
        }
    } WHERE {
        GRAPH <${iri}> {
            <${iri}> a <http://scap.nist.gov/ns/asset-identification#Port> .
            <${iri}> ?p ?o
        }
    }
    `
}

export const deleteIpQuery = (iri) => {
    let rdfType
    if(iri.includes("IpV4")){
        rdfType = "<http://scap.nist.gov/ns/asset-identification#IpV4Address>";
    } else if (iri.includes("IpV6")){
        rdfType = "<http://scap.nist.gov/ns/asset-identification#IpV6Address>";
    } else {
        throw new Error(`Cannot determine IP version from IRI ${iri}`);
    }
    return `
    DELETE {
        GRAPH ${iri} {
            ${iri} ?p ?o
        }
    } WHERE {
        GRAPH ${iri} {
            ${iri} a ${rdfType} .
            ${iri} ?p ?o
        }
    }
    `
}
