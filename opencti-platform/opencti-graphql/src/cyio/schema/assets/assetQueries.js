import { v4 as uuid4, v5 as uuid5 } from 'uuid';
import { DARKLIGHT_NS, generateId, OASIS_SCO_NS } from '../utils.js';

export const insertPortsQuery = (ports) => {
  const iris = [];
  const graphs = [];
  ports.forEach((port) => {
    const id = uuid4();
    const timestamp = new Date().toISOString();
    const insertPredicates = [];
    const iri = `<http://scap.nist.gov/ns/asset-identification#Port-${id}>`;
    iris.push(iri);
    insertPredicates.push(`${iri} a <http://darklight.ai/ns/common#ComplexDatatype>`);
    insertPredicates.push(`${iri} a <http://scap.nist.gov/ns/asset-identification#Port>`);
    insertPredicates.push(`${iri} <http://darklight.ai/ns/common#id> "${id}"`);
    insertPredicates.push(`${iri} <http://darklight.ai/ns/common#object_type> "port"`);
    insertPredicates.push(`${iri} <http://darklight.ai/ns/common#created> "${timestamp}"^^xsd:dateTime`);
    insertPredicates.push(`${iri} <http://darklight.ai/ns/common#modified> "${timestamp}"^^xsd:dateTime`);
    if (port.protocols !== undefined) {
      port.protocols.forEach((protocol) =>
        insertPredicates.push(`${iri} <http://scap.nist.gov/ns/asset-identification#protocols> "${protocol}"`)
      );
    }
    insertPredicates.push(
      `${iri} <http://scap.nist.gov/ns/asset-identification#port_number> "${port.port_number}"^^xsd:positiveInteger`
    );
    const combinedPredicates = insertPredicates.join(' .\n      ');
    graphs.push(`
    GRAPH ${iri} {
        ${combinedPredicates}
    }
        `);
  });
  const query = `
INSERT DATA {
    ${graphs.join('\n')}
}
    `;
  return { iris, query };
};

export const insertPortRelationships = (parentIri, portsIris) => {
  const predicates = portsIris
    .map((port) => `${parentIri} <http://scap.nist.gov/ns/asset-identification#ports> ${port}`)
    .join(' .\n        ');
  return `
INSERT DATA {
    GRAPH ${parentIri} {
        ${predicates}
    }
}
    `;
};

/**
 * @param ip - the IPAddress node
 * @param version - either 4 or 6 (number values)
 */
export const insertIPQuery = (ip, version) => {
  const graphs = [];
  const ipIris = [];
  const timestamp = new Date().toISOString();
  ip.forEach((ip) => {
    const insertPredicates = [];
    const idMaterial = { value: ip.ip_address_value };
    const id = generateId(idMaterial, DARKLIGHT_NS);
    let type;
    let rdfType;
    let iri;
    if (version === 4) {
      type = 'ipv4-addr';
      iri = `<http://scap.nist.gov/ns/asset-identification#IpV4Address-${id}>`;
      rdfType = '<http://scap.nist.gov/ns/asset-identification#IpV4Address>';
    } else if (version === 6) {
      type = 'ipv6-addr';
      iri = `<http://scap.nist.gov/ns/asset-identification#IpV6Address-${id}>`;
      rdfType = '<http://scap.nist.gov/ns/asset-identification#IpV6Address>';
    } else {
      throw new Error(`Invalid IP address version: ${version}`);
    }
    ipIris.push(iri);
    insertPredicates.push(`${iri} a ${rdfType}`);
    insertPredicates.push(`${iri} a <http://scap.nist.gov/ns/asset-identification#IpAddress>`);
    insertPredicates.push(`${iri} <http://darklight.ai/ns/common#id> "${id}"`);
    insertPredicates.push(
      `${iri} <http://scap.nist.gov/ns/asset-identification#ip_address_value> "${ip.ip_address_value}"`
    );
    insertPredicates.push(`${iri} <http://darklight.ai/ns/common#object_type> "${type}"`);
    insertPredicates.push(`${iri} <http://darklight.ai/ns/common#created> "${timestamp}"^^xsd:dateTime`);
    insertPredicates.push(`${iri} <http://darklight.ai/ns/common#modified> "${timestamp}"^^xsd:dateTime`);
    graphs.push(`
    GRAPH ${iri} {
        ${insertPredicates.join('.\n        ')}
    }    
        `);
  });
  const query = `
INSERT DATA {
    ${graphs.join('\n    ')}
}
    `;
  return { ipIris, query };
};

/**
 * @param parentIri - the object of the relationship. (THIS ASSUMES GRAPHS)
 * @param ipIri - iri of the existing IP object
 */
export const insertIPRelationship = (parentIri, ipIris) => {
  if (!parentIri.startsWith('<')) parentIri = `<${parentIri}>`;
  const predicates = ipIris
    .map((ipIri) => `${parentIri} <http://scap.nist.gov/ns/asset-identification#ip_address> ${ipIri}`)
    .join('.\n        ');
  return `
INSERT DATA {
    GRAPH ${parentIri} {
        ${predicates}
    }
}
    `;
};

/**
 * @param mac - the mac string
 */
export const insertMACQuery = (mac) => {
  const graphs = [];
  const macIris = [];
  const timestamp = new Date().toISOString();
  if (Array.isArray(mac)) {
    const macList = [];
    for (const macAddr of mac) {
      macList.push({ mac_address_value: macAddr, is_virtual: false });
    }
    mac = macList;
  }
  mac.forEach((mac) => {
    const insertPredicates = [];
    const idMaterial = { value: mac.mac_address_value };
    const id = generateId(idMaterial, DARKLIGHT_NS);
    let type;
    let rdfType;
    let iri;
    type = 'mac-addr';
    iri = `<http://scap.nist.gov/ns/asset-identification#MACAddress-${id}>`;

    macIris.push(iri);
    insertPredicates.push(`${iri} a <http://scap.nist.gov/ns/asset-identification#MACAddress>`);
    insertPredicates.push(`${iri} <http://darklight.ai/ns/common#id> "${id}"`);
    insertPredicates.push(`${iri} <http://darklight.ai/ns/common#object_type> "${type}"`);
    insertPredicates.push(`${iri} <http://darklight.ai/ns/common#created> "${timestamp}"^^xsd:dateTime`);
    insertPredicates.push(`${iri} <http://darklight.ai/ns/common#modified> "${timestamp}"^^xsd:dateTime`);
    insertPredicates.push(
      `${iri} <http://scap.nist.gov/ns/asset-identification#mac_address_value> "${mac.mac_address_value}"`
    );
    graphs.push(`
    GRAPH ${iri} {
        ${insertPredicates.join('.\n        ')}
    }    
        `);
  });
  const query = `
INSERT DATA {
    ${graphs.join('\n    ')}
}
    `;
  return { macIris, query };
};

/**
 * @param parentIri - the object of the relationship. (THIS ASSUMES GRAPHS)
 * @param macIri - iri of the existing MAC object
 */
export const insertMACRelationship = (parentIri, macIris) => {
  if (!parentIri.startsWith('<')) parentIri = `<${parentIri}>`;
  const predicates = macIris
    .map((macIri) => `${parentIri} <http://scap.nist.gov/ns/asset-identification#mac_address> ${macIri}`)
    .join('.\n        ');
  return `
INSERT DATA {
    GRAPH ${parentIri} {
        ${predicates}
    }
}
    `;
};

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
    `;
};

export const deleteIpQuery = (iri) => {
  let rdfType;
  if (iri.includes('IpV4')) {
    rdfType = '<http://scap.nist.gov/ns/asset-identification#IpV4Address>';
  } else if (iri.includes('IpV6')) {
    rdfType = '<http://scap.nist.gov/ns/asset-identification#IpV6Address>';
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
    `;
};

export const deleteMacQuery = (iri) => {
  let rdfType;
  rdfType = '<http://scap.nist.gov/ns/asset-identification#MACAddress>';
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
    `;
};

export const insertIPAddressRangeQuery = (startingIri, endingIri) => {
  const id = uuid4();
  const timestamp = new Date().toISOString();
  const iri = `<http://scap.nist.gov/ns/asset-identification#IpAddressRange-${id}>`;
  const query = `
    INSERT DATA {
        GRAPH ${iri} {
            ${iri} a <http://scap.nist.gov/ns/asset-identification#IpAddressRange> ;
                <http://darklight.ai/ns/common#id> "${id}";
                <http://scap.nist.gov/ns/asset-identification#starting_ip_address> ${startingIri} ;
                <http://scap.nist.gov/ns/asset-identification#ending_ip_address> ${endingIri} .
                ${iri} <http://darklight.ai/ns/common#object_type> "ip-addr-range" . 
                ${iri} <http://darklight.ai/ns/common#created> "${timestamp}"^^xsd:dateTime . 
                ${iri} <http://darklight.ai/ns/common#modified> "${timestamp}"^^xsd:dateTime .           
            }
    }
    `;
  return { iri, query };
};

export const insertIPAddressRangeRelationship = (parentIri, rangeIri) => {
  if (!parentIri.startsWith('<')) parentIri = `<${parentIri}>`;
  return `
    INSERT DATA {
        GRAPH ${parentIri} {
            ${parentIri} <http://scap.nist.gov/ns/asset-identification#network_address_range> ${rangeIri} .
        }
    }
    `;
};

export const selectIPAddressRange = (iri) => {
  return `
SELECT DISTINCT ?id ?object_type ?starting_ip_address ?ending_ip_address 
FROM <tag:stardog:api:context:named>
WHERE {
    ${iri} a <http://scap.nist.gov/ns/asset-identification#IpAddressRange> ;
        <http://darklight.ai/ns/common#id> ?id  ;
        <http://scap.nist.gov/ns/asset-identification#starting_ip_address> ?starting_ip_address ;
        <http://scap.nist.gov/ns/asset-identification#ending_ip_address> ?ending_ip_address .
    OPTIONAL { ${iri} <http://darklight.ai/ns/common#object_type> ?object_type } .
}`;
  //     return `
  // SELECT DISTINCT ?id ?object_type ?starting_ip_address ?ending_ip_address
  // FROM <tag:stardog:api:context:named>
  // WHERE {
  // #  GRAPH ${iri} {
  //     ${iri} a <http://scap.nist.gov/ns/asset-identification#IpAddressRange> ;
  //         <http://darklight.ai/ns/common#id> ?id  ;
  //         <http://scap.nist.gov/ns/asset-identification#starting_ip_address> ?starting_ip_address ;
  //         <http://scap.nist.gov/ns/asset-identification#ending_ip_address> ?ending_ip_address .
  //     OPTIONAL { ${iri} <http://darklight.ai/ns/common#object_type> ?object_type } .
  // #  }
  // }`
};

export const deleteIpAddressRange = (iri) => {
  return `
    DELETE {
        GRAPH ${iri} {
            ${iri} ?p ?o
        }
    } WHERE {
        GRAPH ${iri} {
            ${iri} a <http://scap.nist.gov/ns/asset-identification#IpAddressRange> .
            ${iri} ?p ?o
        }
    }
    `;
};
