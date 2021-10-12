# !/usr/bin/env python3
#  -*- coding: UTF-8 -*-
"""
gen_graphQL - generates a JSON representation of the classes, namespaces, and prefixes
              defined in the ontologies loaded.

              this utility can also be utilizes to verify the ontology files submited
              to ensure there are no syntax issues

              Base on code from ONTOSPY 
"""

from __future__ import print_function
import sys, os, io, time, optparse

from rdflib.term import BNode
try:
    import urllib2
except ImportError:
    import urllib.request as urllib2

import click
import rdflib
import json



class RDFLoader(object):
    """
    Utility to Load any RDF source into an RDFLIB graph instance.

    Accepts: [single item or list]
    :: uri_or_path = a uri or local path
    :: data = a string containing rdf
    :: file_obj = a python file object

    Returns: rdflib graph instance.

    Other options:
    :: rdf_format = one of ['xml', 'turtle', 'n3', 'nt', 'trix', 'rdfa']
    :: verbose = if True, prints out a summary of loading operations

    Note : you can pass lists, with the effect that the resulting graph
    will be a union of the rdf data contained in each of the arguments

    @TODO: refactor so that verbose is always taken from INIT method

    """

    SERIALIZATIONS = [
        'xml',
        'n3',
        'nt',
        'json-ld',
        'turtle',
        'rdfa',
    ]

    def __init__(self, rdfgraph=None, verbose=False):
        super(RDFLoader, self).__init__()

        self.rdflib_graph = rdfgraph or rdflib.Graph()
        self.sources_valid = []
        self.sources_invalid = []
        self.verbose = verbose

    def _debugGraph(self):
        """internal util to print out contents of graph"""
        print("Len of graph: ", len(self.rdflib_graph))
        for x, y, z in self.rdflib_graph:
            print(x, y, z)

    def load(self, uri_or_path=None, data=None, file_obj=None, rdf_format=""):

        if not rdf_format:
            self.rdf_format_opts = self.SERIALIZATIONS
        else:
            self.rdf_format_opts = [rdf_format]

        # URI OR PATH
        if uri_or_path:
            if not type(uri_or_path) in [list, tuple]:
                uri_or_path = [uri_or_path]
            for candidate in uri_or_path:
                if os.path.isdir(candidate):
                    # inner loop in case it's a folder
                    temp = get_files_with_extensions(candidate, [
                        "ttl", "rdf", "xml", "trix", "rdfa", "n3", "nq",
                        "jsonld", "nt"
                    ])
                else:
                    # fake a one-element list
                    temp = [candidate]
                # finally:
                for each in temp:
                    uri = self.resolve_redirects_if_needed(each)
                    self.load_uri(uri)

        # DATA STRING
        elif data:
            if not type(data) in [list, tuple]:
                data = [data]
            for each in data:
                self.load_data(each)

        # FILE OBJECT
        elif file_obj:
            if not type(file_obj) in [list, tuple]:
                file_obj = [file_obj]
            for each in file_obj:
                self.load_file(each)

        else:
            raise Exception("You must specify where to load RDF from.")

        if self.verbose: self.print_summary()

        return self.rdflib_graph

    def load_uri(self, uri):
        """
        Load a single resource into the graph for this object. 

        Approach: try loading into a temporary graph first, if that succeeds merge it into the main graph. This allows to deal with the JSONLD loading issues which can solved only by using a  ConjunctiveGraph (https://github.com/RDFLib/rdflib/issues/436). Also it deals with the RDFA error message which seems to stick into a graph even if the parse operation fails. 
        
        NOTE the final merge operation can be improved as graph-set operations involving blank nodes could case collisions (https://rdflib.readthedocs.io/en/stable/merging.html)  

        :param uri: single RDF source location
        :return: None (sets self.rdflib_graph and self.sources_valid)
        """

        # if self.verbose: printDebug("----------")
        if self.verbose: printDebug("Reading: <%s>" % uri, fg="green")
        success = False

        sorted_fmt_opts = try_sort_fmt_opts(self.rdf_format_opts, uri)

        for f in sorted_fmt_opts:
            if self.verbose:
                printDebug(".. trying rdf serialization: <%s>" % f)
            try:
                if f == 'json-ld':
                    if self.verbose:
                        printDebug(
                            "Detected JSONLD - loading data into rdflib.ConjunctiveGraph()",
                            fg='green')
                    temp_graph = rdflib.ConjunctiveGraph()
                else:
                    temp_graph = rdflib.Graph()
                temp_graph.parse(uri, format=f)
                if self.verbose: printDebug("..... success!", bold=True)
                success = True
                self.sources_valid += [uri]
                # ok, so merge
                self.rdflib_graph = self.rdflib_graph + temp_graph
                break
            except:
                temp = None
                if self.verbose: printDebug("..... failed")
                # self._debugGraph()

        if not success == True:
            self.loading_failed(sorted_fmt_opts, uri=uri)
            self.sources_invalid += [uri]

    def load_data(self, data):
        """

        :param data:
        :param rdf_format_opts:
        :return:
        """
        if self.verbose: printDebug("----------")
        if self.verbose: printDebug("Reading: '%s ...'" % data[:10])
        success = False
        for f in self.rdf_format_opts:
            if self.verbose:
                printDebug(".. trying rdf serialization: <%s>" % f)
            try:
                if f == 'json-ld':
                    self._fix_default_graph_for_jsonld()
                self.rdflib_graph.parse(data=data, format=f)
                if self.verbose: printDebug("..... success!")
                success = True
                self.sources_valid += ["Data: '%s ...'" % data[:10]]
                break
            except:
                if self.verbose: printDebug("..... failed", "error")

        if not success == True:
            self.loading_failed(self.rdf_format_opts)
            self.sources_invalid += ["Data: '%s ...'" % data[:10]]

    def load_file(file_obj):
        """
        The type of open file objects such as sys.stdout; alias of the built-in file.
        @TODO: when is this used?
        """
        if self.verbose: printDebug("----------")
        if self.verbose: printDebug("Reading: <%s> ...'" % file_obj.name)

        if type(file_obj) == file:
            self.rdflib_graph = self.rdflib_graph + file_obj
            self.sources_valid += [file_obj.NAME]
        else:
            self.loading_failed(self.rdf_format_opts)
            self.sources_invalid += [file_obj.NAME]

    def resolve_redirects_if_needed(self, uri):
        """
        substitute with final uri after 303 redirects (if it's a www location!)
        :param uri:
        :return:
        """
        if type(uri) == type("string") or type(uri) == type(u"unicode"):

            if uri.startswith("www."):  # support for lazy people
                uri = "http://%s" % str(uri)
            if uri.startswith("http://"):
                # headers = "Accept: application/rdf+xml"  # old way
                headers = {'Accept': "application/rdf+xml"}
                req = urllib2.Request(uri, headers=headers)
                res = urllib2.urlopen(req)
                uri = res.geturl()

        else:
            raise Exception("A URI must be in string format.")

        return uri

    def print_summary(self):
        """
        print out stats about loading operation
        """
        if self.sources_valid:
            printDebug(
                "----------\nLoaded %d triples.\n----------" % len(
                    self.rdflib_graph),
                fg='white')
            printDebug(
                "RDF sources loaded successfully: %d of %d." %
                (len(self.sources_valid),
                 len(self.sources_valid) + len(self.sources_invalid)),
                fg='green')
            for s in self.sources_valid:
                printDebug("..... '" + s + "'", fg='white')
            printDebug("----------", fg='white')
        else:
            printDebug("Sorry - no valid RDF was found", fg='red')

        if self.sources_invalid:
            printDebug(
                "----------\nRDF sources failed to load: %d.\n----------" %
                (len(self.sources_invalid)),
                fg='red')
            for s in self.sources_invalid:
                printDebug("-> " + s, fg="red")

    def loading_failed(self, rdf_format_opts, uri=""):
        """default message if we need to abort loading"""
        if uri:
            uri = " <%s>" % str(uri)
        printDebug(
            "----------\nFatal error parsing graph%s\n(using RDF serializations: %s)"
            % (uri, str(rdf_format_opts)), "red")
        printDebug(
            "----------\nTIP: You can try one of the following RDF validation services\n<http://mowl-power.cs.man.ac.uk:8080/validator/validate>\n<http://www.ivan-herman.net/Misc/2008/owlrl/>"
        )

        return

    def get_namespaces( self ):
        #
        # build a dictionary of namespace URIs and corresponding prefixes
        #
        namespaces = {}
        for prefix, ns_iri in self.rdflib_graph.namespace_manager.namespaces():
            namespaces[prefix] = ns_iri.toPython()
        
        return( namespaces )


    def get_classes( self ):
        #
        # Build a collection of nodes for each class in the ontologies
        #
        classResults = self.rdflib_graph.query(
            """SELECT DISTINCT ?iri ?label ?comment ?parentIri
                WHERE {
                    ?iri rdf:type  owl:Class .
                    OPTIONAL {?iri rdfs:subClassOf ?parentIri} .
                    OPTIONAL {?iri rdfs:label ?label} .
                    OPTIONAL {?iri rdfs:comment ?comment} .
                }
            """
        )

        classes = {}
        for iri, label, comment, parent in classResults:
            # skip blank node classes
            if  isinstance(iri, rdflib.term.BNode):
                continue

            node = classes.get(iri.n3(self.rdflib_graph.namespace_manager))
            if node is None:
                node = {}
                node['iri'] = iri.toPython()
                node['name'] = iri.toPython().split('#')[1] if '#' in iri.toPython() else iri.n3(self.rdflib_graph.namespace_manager).split(':')[1]
                node['simple'] = iri.n3(self.rdflib_graph.namespace_manager)

                if self.verbose is True: printDebug("...   Found class %s" % node['simple'], fg="green")

                # add node for class to the class dictionary
                classes[node['simple']] = node

            # handle literals with language tags
            if label is not None and '@en' in label.n3() and 'label' not in node:
                node['label'] = label.n3().split('@')[0]
                node['label'] = node['label'][1:len(node['label']) -1]
            if comment is not None and '@en' in comment.n3() and 'comment' not in node:
                node['comment'] = comment.n3().split('@')[0]
                node['comment'] = node['comment'][1:len(node['comment']) -1]

            # capture parent class if not owl:Thing or a blank node
            if parent is not None:
                if not isinstance(parent, rdflib.term.BNode) and parent.toPython() != 'http://www.w3.org/2002/07/owl#Thing' and 'subClassOf' not in node:
                    node['subClassOf'] = parent.n3(self.rdflib_graph.namespace_manager)
                elif isinstance(parent, rdflib.term.BNode):
                    # check if restriction for cardinality
                    if 'restrictions' not in node:
                        node['restrictions'] = {}
                    
                    if parent.n3(self.rdflib_graph.namespace_manager) not in node['restrictions']:
                        restriction = self.get_restriction( parent )
                        node['restrictions'][parent.n3(self.rdflib_graph.namespace_manager)] = restriction
                    else:
                        printDebug("Unhandled restriction value", fg="red")

        return( classes if len(classes) else None )


    def get_restriction( self, bnode_iri):
        #
        # Build a restriction definition for the specified BNode IRI
        #
        restriction = {}
        for subject, predicate, object in self.rdflib_graph.triples((bnode_iri, None, None)):
            simple_predicate = predicate.n3(self.rdflib_graph.namespace_manager) 
            if simple_predicate == 'rdf:type':
                continue
            elif simple_predicate == 'owl:onProperty':
                restriction['onProperty'] = object.n3(self.rdflib_graph.namespace_manager)
            elif 'value' or 'cardinality' in simple_predicate.lower() :
                restriction['type'] = simple_predicate.split(':')[1]
                restriction['value'] = object.toPython()

        return( restriction if len(restriction) else None )


    def get_predicates_for_class( self, class_iri ):
        #
        # Build a collection of nodes for each predicate of the specified class
        #
        query_str = """SELECT DISTINCT ?iri ?type ?range ?label ?comment ?parentIRI
                        WHERE { 
                            ?iri rdfs:domain <%s> . 
                            ?iri rdf:type ?type .
                            OPTIONAL { ?iri rdfs:range ?range } .
                            OPTIONAL { ?iri rdfs:subClassOf ?parentIri } .
                            OPTIONAL { ?iri rdfs:label ?label } .
                            OPTIONAL { ?iri rdfs:comment ?comment } .
                        }
                    """ % class_iri

        results = self.rdflib_graph.query( query_str )

        predicates = {}
        for iri, type, range, label, comment, parent in results:
            # skip blank node 
            if  isinstance(iri, rdflib.term.BNode):
                continue

            node = predicates.get(iri.n3(self.rdflib_graph.namespace_manager))
            if node is None:
                node = {}
                node['iri'] = iri.toPython()
                node['name'] = iri.toPython().split('#')[1] if '#' in iri.toPython() else iri.n3(self.rdflib_graph.namespace_manager).split(':')[1]
                node['simple'] = iri.n3(self.rdflib_graph.namespace_manager)
                node['type'] = type.toPython()

                if self.verbose is True: printDebug("...   Found predicate %s" % node['simple'], fg="green")

                # add node for class to the class dictionary
                predicates[node['simple']] = node

            # handle range which could be a value or a BNode
            if range is not None: 
                if 'range' not in node:
                    node['range'] = {}
                
                # see if it already exists
                constraint = node['range'].get(range.n3(self.rdflib_graph.namespace_manager))
                if constraint is not None:
                    continue

                if not isinstance(range, rdflib.term.BNode):
                    # this is a simple, singular datatype
                    if type.toPython() not in node['range']:
                        node['range'] = {type.n3(self.rdflib_graph.namespace_manager): [range.n3(self.rdflib_graph.namespace_manager)]}
                else:
                    # Encountered BNode which means its either a data restriction,
                    # unionOf objects (owl:unionOf), or an enumeration of values (owl:oneOf)
                    range_definition = self.get_range_definition( range )
                    node['range'] = range_definition
            else:
                node['range'] = 'http://www.w3.org/2002/07/owl#Thing'

            # handle literals with language tags
            if label is not None and '@en' in label.n3() and 'label' not in node:
                node['label'] = label.n3().split('@')[0]
                node['label'] = node['label'][1:len(node['label']) -1]
            if comment is not None and '@en' in comment.n3() and 'comment' not in node:
                node['comment'] = comment.n3().split('@')[0]
                node['comment'] = node['comment'][1:len(node['comment']) -1]

            # capture parent property if not owl:Thing or a blank node
            if parent is not None and not isinstance(parent, rdflib.term.BNode) and parent.toPython() != 'http://www.w3.org/2002/07/owl#Thing' and 'subClassOf' not in node:
                node['subClassOf'] = parent.n3(self.rdflib_graph.namespace_manager)

        return( predicates if len(predicates) else None )

    def get_range_definition(self, bnode_iri):
        #
        # Build a range definition for the specified BNode IRI
        #
        range_definition = {}
        for subject, predicate, object in self.rdflib_graph.triples((bnode_iri, None, None)):
            simple_predicate = predicate.n3(self.rdflib_graph.namespace_manager)
            if simple_predicate.lower() == 'rdf:type':
                continue
            elif ('unionOf' in simple_predicate) or ('oneOf' in simple_predicate):
                values = self.get_constraint_values( object )
                if len(values):
                    range_definition = {simple_predicate.split(':')[1]: values }
            elif 'onDatatype' in simple_predicate:
                range_definition[simple_predicate.split(':')[1]] = [object.n3(self.rdflib_graph.namespace_manager)]
            elif 'withRestrictions' in simple_predicate:
                values = self.get_constraint_values( object )
                if isinstance(values[0], rdflib.term.BNode):
                    for s, p, o in self.rdflib_graph.triples((values[0], None, None)):
                        range_definition[p.n3(self.rdflib_graph.namespace_manager).split(':')[1]] = [o.n3(self.rdflib_graph.namespace_manager)]
            else:
                continue


        return (range_definition if len(range_definition) else None )

    def get_constraint_values( self, bnode_iri):
        state = {}
        for subject, predicate, object in self.rdflib_graph.triples((bnode_iri, None, None)):
            simple_predicate = predicate.n3(self.rdflib_graph.namespace_manager)
            if simple_predicate == 'rdf:first':
                if not isinstance(object, rdflib.term.BNode):
                    state['first'] = object.toPython()
                else:
                    state['first'] = object
            elif simple_predicate == 'rdf:rest':
                if isinstance(object, rdflib.term.BNode):
                    state['rest'] = object
            else:
                continue

        values = [state['first']]
        if 'rest' in state and isinstance( state['rest'], rdflib.term.BNode):
            value = self.get_constraint_values(state['rest'])
            values.extend(value)

        return( values )




def printDebug(text, mystyle="", **kwargs):
    """
    util for printing in colors using click.secho()

    :kwargs = you can do printDebug("s", bold=True)

    2018-12-06: by default print to standard error (err=True)

    Styling output:
    <http://click.pocoo.org/5/api/#click.style>
    Styles a text with ANSI styles and returns the new string. By default the styling is self contained which means that at the end of the string a reset code is issued. This can be prevented by passing reset=False.

    Examples:

    click.echo(click.style('Hello World!', fg='green'))
    click.echo(click.style('ATTENTION!', blink=True))
    click.echo(click.style('Some things', reverse=True, fg='cyan'))
    Supported color names:

    black (might be a gray)
    red
    green
    yellow (might be an orange)
    blue
    magenta
    cyan
    white (might be light gray)
    reset (reset the color code only)
    New in version 2.0.

    Parameters:
    text – the string to style with ansi codes.
    fg – if provided this will become the foreground color.
    bg – if provided this will become the background color.
    bold – if provided this will enable or disable bold mode.
    dim – if provided this will enable or disable dim mode. This is badly supported.
    underline – if provided this will enable or disable underline.
    blink – if provided this will enable or disable blinking.
    reverse – if provided this will enable or disable inverse rendering (foreground becomes background and the other way round).
    reset – by default a reset-all code is added at the end of the string which means that styles do not carry over. This can be disabled to compose styles.

    """

    if mystyle == "comment":
        click.secho(text, dim=True, err=True)
    elif mystyle == "important":
        click.secho(text, bold=True, err=True)
    elif mystyle == "normal":
        click.secho(text, reset=True, err=True)
    elif mystyle == "red" or mystyle == "error":
        click.secho(text, fg='red', err=True)
    elif mystyle == "green":
        click.secho(text, fg='green', err=True)
    else:
        click.secho(text, **kwargs)


def get_files_with_extensions(folder, extensions):
    """walk dir and return .* files as a list
    Note: directories are walked recursively"""
    out = []
    for root, dirs, files in os.walk(folder):
        for file in files:
            filename, file_extension = os.path.splitext(file)
            if file_extension.replace(".", "") in extensions:
                out += [os.path.join(root, file)]
                # break

    return out

def try_sort_fmt_opts(rdf_format_opts_list, uri):
    """reorder fmt options based on uri file type suffix - if available - so to test most likely serialization first when parsing some RDF 

    NOTE this is not very nice as it is hardcoded and assumes the origin serializations to be this: ['turtle', 'xml', 'n3', 'nt', 'json-ld', 'rdfa']
    
    """
    filename, file_extension = os.path.splitext(uri)
    # print(filename, file_extension)
    if file_extension == ".ttl" or file_extension == ".turtle":
        return ['turtle', 'n3', 'nt', 'json-ld', 'rdfa', 'xml']
    elif file_extension == ".xml" or file_extension == ".rdf":
        return ['xml', 'turtle', 'n3', 'nt', 'json-ld', 'rdfa']
    elif file_extension == ".nt" or file_extension == ".n3":
        return ['n3', 'nt', 'turtle', 'xml', 'json-ld', 'rdfa']
    elif file_extension == ".json" or file_extension == ".jsonld":
        return [
            'json-ld',
            'rdfa',
            'n3',
            'nt',
            'turtle',
            'xml',
        ]
    elif file_extension == ".rdfa":
        return [
            'rdfa',
            'json-ld',
            'n3',
            'nt',
            'turtle',
            'xml',
        ]
    else:
        return rdf_format_opts_list


##
# command line options and arguments
##
@click.command()
@click.argument('uri_or_path', nargs=-1, required=True, type=click.STRING)
@click.option('--verbose', is_flag=True, help='Turn on verbose mode.')
@click.option('--gen_json', type=click.File(mode='w',encoding='utf-8'), help='Generates a JSON respentation of the classes, namespaces, and their prefixes')

##
# command line main
##
def main(uri_or_path, verbose, gen_json):
    loader = RDFLoader(verbose=verbose)

    if verbose is True: printDebug("Generating loading ontologies", fg="green")
    graph = loader.load(uri_or_path)

    ##
    # generate JSON
    ##
    if gen_json:
        #
        # build a dictionary of namespace URIs and corresponding prefixes
        #
        if verbose is True: printDebug("Retrieving namespaces ... ", fg="green")
        namespaces = loader.get_namespaces()

        #
        # Build a collection of nodes for each class in the ontologies
        #
        if verbose is True: printDebug("Retrieving class definitions ... ", fg="green")
        classes = loader.get_classes()

        # get the  predicates for each class
        for key, node in classes.items():
            if verbose is True: printDebug("Determining class %s predicates" % node['simple'], fg="green")
            predicates = loader.get_predicates_for_class(node['iri'])
            if predicates is not None:
                node['predicates'] = predicates

        # generate JSON output to a file
        if gen_json:
            # with io.open( json, 'w', encoding='utf-8' ) as f:
            json.dump( classes, gen_json, sort_keys=True, separators=(',', ':'), indent=4 )

        if verbose is True:
            print(json.dumps( classes, sort_keys=True, separators=(', ', ': '), indent=4))


if __name__ == '__main__':
    """
    simple test: python -m ontospy.core.rdf_loader [PATH] [OPTIONS]
    """
    main()
    printDebug("Finished")
