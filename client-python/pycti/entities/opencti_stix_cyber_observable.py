# coding: utf-8

import base64
import json
import os

import magic

from .indicator.opencti_indicator_properties import INDICATOR_PROPERTIES
from .stix_cyber_observable.opencti_stix_cyber_observable_deprecated import (
    StixCyberObservableDeprecatedMixin,
)
from .stix_cyber_observable.opencti_stix_cyber_observable_properties import (
    SCO_PROPERTIES,
    SCO_PROPERTIES_WITH_FILES,
)


class StixCyberObservable(StixCyberObservableDeprecatedMixin):
    """Main StixCyberObservable class for OpenCTI

    Manages STIX cyber observables (indicators of compromise) in the OpenCTI platform.
    Note: Deprecated methods are available through StixCyberObservableDeprecatedMixin.

    :param opencti: instance of :py:class:`~pycti.api.opencti_api_client.OpenCTIApiClient`
    :param file: file handling configuration
    """

    def __init__(self, opencti, file):

        self.opencti = opencti
        self.file = file
        self.properties = SCO_PROPERTIES
        self.properties_with_files = SCO_PROPERTIES_WITH_FILES

    """
        List StixCyberObservable objects

        :param types: the array of types
        :param filters: the filters to apply
        :param search: the search keyword
        :param first: return the first n rows from the after ID (or the beginning if not set)
        :param after: ID of the first row
        :return List of StixCyberObservable objects
    """

    def list(self, **kwargs):
        types = kwargs.get("types", None)
        filters = kwargs.get("filters", None)
        search = kwargs.get("search", None)
        first = kwargs.get("first", 100)
        after = kwargs.get("after", None)
        order_by = kwargs.get("orderBy", None)
        order_mode = kwargs.get("orderMode", None)
        custom_attributes = kwargs.get("customAttributes", None)
        get_all = kwargs.get("getAll", False)
        with_pagination = kwargs.get("withPagination", False)
        with_files = kwargs.get("withFiles", False)

        self.opencti.app_logger.info(
            "Listing StixCyberObservables with filters",
            {"filters": json.dumps(filters)},
        )
        query = (
            """
                    query StixCyberObservables($types: [String], $filters: FilterGroup, $search: String, $first: Int, $after: ID, $orderBy: StixCyberObservablesOrdering, $orderMode: OrderingMode) {
                        stixCyberObservables(types: $types, filters: $filters, search: $search, first: $first, after: $after, orderBy: $orderBy, orderMode: $orderMode) {
                            edges {
                                node {
                                    """
            + (
                custom_attributes
                if custom_attributes is not None
                else (self.properties_with_files if with_files else self.properties)
            )
            + """
                        }
                    }
                    pageInfo {
                        startCursor
                        endCursor
                        hasNextPage
                        hasPreviousPage
                        globalCount
                    }
                }
            }
        """
        )
        result = self.opencti.query(
            query,
            {
                "types": types,
                "filters": filters,
                "search": search,
                "first": first,
                "after": after,
                "orderBy": order_by,
                "orderMode": order_mode,
            },
        )

        if get_all:
            final_data = []
            data = self.opencti.process_multiple(result["data"]["stixCyberObservables"])
            final_data = final_data + data
            while result["data"]["stixCyberObservables"]["pageInfo"]["hasNextPage"]:
                after = result["data"]["stixCyberObservables"]["pageInfo"]["endCursor"]
                self.opencti.app_logger.info(
                    "Listing StixCyberObservables", {"after": after}
                )
                result = self.opencti.query(
                    query,
                    {
                        "types": types,
                        "filters": filters,
                        "search": search,
                        "first": first,
                        "after": after,
                        "orderBy": order_by,
                        "orderMode": order_mode,
                    },
                )
                data = self.opencti.process_multiple(
                    result["data"]["stixCyberObservables"]
                )
                final_data = final_data + data
            return final_data
        else:
            return self.opencti.process_multiple(
                result["data"]["stixCyberObservables"], with_pagination
            )

    """
        Read a StixCyberObservable object

        :param id: the id of the StixCyberObservable
        :param filters: the filters to apply if no id provided
        :return StixCyberObservable object
    """

    def read(self, **kwargs):
        id = kwargs.get("id", None)
        filters = kwargs.get("filters", None)
        custom_attributes = kwargs.get("customAttributes", None)
        with_files = kwargs.get("withFiles", False)
        if id is not None:
            self.opencti.app_logger.info("Reading StixCyberObservable", {"id": id})
            query = (
                """
                        query StixCyberObservable($id: String!) {
                            stixCyberObservable(id: $id) {
                                """
                + (
                    custom_attributes
                    if custom_attributes is not None
                    else (self.properties_with_files if with_files else self.properties)
                )
                + """
                    }
                }
             """
            )
            result = self.opencti.query(query, {"id": id})
            return self.opencti.process_multiple_fields(
                result["data"]["stixCyberObservable"]
            )
        elif filters is not None:
            result = self.list(filters=filters, customAttributes=custom_attributes)
            if len(result) > 0:
                return result[0]
            else:
                return None
        else:
            self.opencti.app_logger.error(
                "[opencti_stix_cyber_observable] Missing parameters: id or filters"
            )
            return None

    """
        Upload a file in this Observable

        :param id: the Stix-Cyber-Observable id
        :param file_name
        :param data
        :return void
    """

    def add_file(self, **kwargs):
        id = kwargs.get("id", None)
        file_name = kwargs.get("file_name", None)
        data = kwargs.get("data", None)
        file_markings = kwargs.get("fileMarkings", None)
        version = kwargs.get("version", None)
        mime_type = kwargs.get("mime_type", "text/plain")
        no_trigger_import = kwargs.get("no_trigger_import", False)
        embedded = kwargs.get("embedded", False)
        if id is not None and file_name is not None:
            final_file_name = os.path.basename(file_name)
            query = """
                    mutation StixCyberObservableEdit($id: ID!, $file: Upload!, $fileMarkings: [String], $version: DateTime, $noTriggerImport: Boolean, $embedded: Boolean) {
                        stixCyberObservableEdit(id: $id) {
                            importPush(file: $file, version: $version, fileMarkings: $fileMarkings, noTriggerImport: $noTriggerImport, embedded: $embedded) {
                                id
                                name
                            }
                        }
                    }
                 """
            if data is None:
                data = open(file_name, "rb")
                if file_name.endswith(".json"):
                    mime_type = "application/json"
                else:
                    mime_type = magic.from_file(file_name, mime=True)
            self.opencti.app_logger.info(
                "Uploading a file in Stix-Cyber-Observable",
                {"file": final_file_name, "id": id},
            )
            return self.opencti.query(
                query,
                {
                    "id": id,
                    "file": (self.file(final_file_name, data, mime_type)),
                    "fileMarkings": file_markings,
                    "version": version,
                    "noTriggerImport": (
                        no_trigger_import
                        if isinstance(no_trigger_import, bool)
                        else no_trigger_import == "True"
                    ),
                    "embedded": embedded,
                },
            )
        else:
            self.opencti.app_logger.error(
                "[opencti_stix_cyber_observable Missing parameters: id or file_name"
            )
            return None

    """
        Create a Stix-Observable object

        :param observableData: the data of the observable (STIX2 structure)
        :return Stix-Observable object
    """

    def create(self, **kwargs):
        observable_data = kwargs.get("observableData", {})
        simple_observable_id = kwargs.get("simple_observable_id", None)
        simple_observable_key = kwargs.get("simple_observable_key", None)
        simple_observable_value = kwargs.get("simple_observable_value", None)
        simple_observable_description = kwargs.get(
            "simple_observable_description", None
        )
        x_opencti_score = kwargs.get("x_opencti_score", None)
        created_by = kwargs.get("createdBy", None)
        object_marking = kwargs.get("objectMarking", None)
        object_label = kwargs.get("objectLabel", None)
        external_references = kwargs.get("externalReferences", None)
        granted_refs = kwargs.get("objectOrganization", None)
        update = kwargs.get("update", False)

        create_indicator = (
            observable_data["x_opencti_create_indicator"]
            if "x_opencti_create_indicator" in observable_data
            else kwargs.get("createIndicator", False)
        )
        attribute = None
        if simple_observable_key is not None:
            key_split = simple_observable_key.split(".")
            type = key_split[0].title()
            attribute = key_split[1]
            if attribute not in ["hashes", "extensions"]:
                observable_data[attribute] = simple_observable_value
        else:
            type = (
                observable_data["type"].title() if "type" in observable_data else None
            )
        if type is None:
            return
        if type.lower() == "file":
            type = "StixFile"
        elif type.lower() == "ipv4-addr":
            type = "IPv4-Addr"
        elif type.lower() == "ipv6-addr":
            type = "IPv6-Addr"
        elif type.lower() == "persona":
            type = "Persona"
        elif type.lower() == "ssh-key":
            type = "SSH-Key"
        elif type.lower() == "hostname" or type.lower() == "x-opencti-hostname":
            type = "Hostname"
        elif type.lower() == "payment-card" or type.lower() == "x-opencti-payment-card":
            type = "Payment-Card"
        elif type.lower() == "credential" or type.lower() == "x-opencti-credential":
            type = "Credential"
        elif (
            type.lower() == "tracking-number"
            or type.lower() == "x-opencti-tracking-number"
        ):
            type = "Tracking-Number"
        elif (
            type.lower() == "cryptocurrency-wallet"
            or type.lower() == "x-opencti-cryptocurrency-wallet"
        ):
            type = "Cryptocurrency-Wallet"
        elif type.lower() == "user-agent" or type.lower() == "x-opencti-user-agent":
            type = "User-Agent"
        elif (
            type.lower() == "cryptographic-key"
            or type.lower() == "x-opencti-cryptographic-key"
        ):
            type = "Cryptographic-Key"
        elif type.lower() == "imei" or type.lower() == "x-opencti-imei":
            type = "IMEI"
        elif type.lower() == "iccid" or type.lower() == "x-opencti-iccid":
            type = "ICCID"
        elif type.lower() == "imsi" or type.lower() == "x-opencti-imsi":
            type = "IMSI"
        elif type.lower() == "text" or type.lower() == "x-opencti-text":
            type = "Text"

        if "x_opencti_description" in observable_data:
            x_opencti_description = observable_data["x_opencti_description"]
        else:
            x_opencti_description = self.opencti.get_attribute_in_extension(
                "description", observable_data
            )

        if simple_observable_description is not None:
            x_opencti_description = simple_observable_description

        if "x_opencti_score" in observable_data:
            x_opencti_score = observable_data["x_opencti_score"]
        elif (
            self.opencti.get_attribute_in_extension("score", observable_data)
            is not None
        ):
            x_opencti_score = self.opencti.get_attribute_in_extension(
                "score", observable_data
            )

        stix_id = observable_data["id"] if "id" in observable_data else None
        if simple_observable_id is not None:
            stix_id = simple_observable_id

        hashes = []
        if (
            simple_observable_key is not None
            and simple_observable_key.lower() == "file.hashes.md5"
        ):
            hashes.append({"algorithm": "MD5", "hash": simple_observable_value})
        if (
            simple_observable_key is not None
            and simple_observable_key.lower() == "file.hashes.sha-1"
        ):
            hashes.append({"algorithm": "SHA-1", "hash": simple_observable_value})
        if (
            simple_observable_key is not None
            and simple_observable_key.lower() == "file.hashes.sha-256"
        ):
            hashes.append({"algorithm": "SHA-256", "hash": simple_observable_value})
        if "hashes" in observable_data:
            for key, value in observable_data["hashes"].items():
                hashes.append({"algorithm": key, "hash": value})

        if type is not None:
            self.opencti.app_logger.info(
                "Creating Stix-Cyber-Observable",
                {"type": type, "create_indicator": create_indicator},
            )
            input_variables = {
                "type": type,
                "stix_id": stix_id,
                "x_opencti_score": x_opencti_score,
                "x_opencti_description": x_opencti_description,
                "createIndicator": create_indicator,
                "createdBy": created_by,
                "objectMarking": object_marking,
                "objectOrganization": granted_refs,
                "objectLabel": object_label,
                "externalReferences": external_references,
                "update": update,
            }
            query = """
                mutation StixCyberObservableAdd(
                    $type: String!,
                    $stix_id: StixId,
                    $x_opencti_score: Int,
                    $x_opencti_description: String,
                    $createIndicator: Boolean,
                    $createdBy: String,
                    $objectMarking: [String],
                    $objectLabel: [String],
                    $objectOrganization: [String],
                    $externalReferences: [String],
                    $update: Boolean,
                    $AutonomousSystem: AutonomousSystemAddInput,
                    $Directory: DirectoryAddInput,
                    $DomainName: DomainNameAddInput,
                    $EmailAddr: EmailAddrAddInput,
                    $EmailMessage: EmailMessageAddInput,
                    $EmailMimePartType: EmailMimePartTypeAddInput,
                    $Artifact: ArtifactAddInput,
                    $StixFile: StixFileAddInput,
                    $X509Certificate: X509CertificateAddInput,
                    $IPv4Addr: IPv4AddrAddInput,
                    $IPv6Addr: IPv6AddrAddInput,
                    $MacAddr: MacAddrAddInput,
                    $Mutex: MutexAddInput,
                    $NetworkTraffic: NetworkTrafficAddInput,
                    $Process: ProcessAddInput,
                    $Software: SoftwareAddInput,
                    $Url: UrlAddInput,
                    $UserAccount: UserAccountAddInput,
                    $WindowsRegistryKey: WindowsRegistryKeyAddInput,
                    $WindowsRegistryValueType: WindowsRegistryValueTypeAddInput,
                    $CryptographicKey: CryptographicKeyAddInput,
                    $CryptocurrencyWallet: CryptocurrencyWalletAddInput,
                    $Hostname: HostnameAddInput
                    $Text: TextAddInput,
                    $UserAgent: UserAgentAddInput
                    $BankAccount: BankAccountAddInput
                    $PhoneNumber: PhoneNumberAddInput
                    $Credential: CredentialAddInput
                    $TrackingNumber: TrackingNumberAddInput
                    $PaymentCard: PaymentCardAddInput
                    $Persona: PersonaAddInput
                    $MediaContent: MediaContentAddInput
                    $SSHKey: SSHKeyAddInput
                    $IMEI: IMEIAddInput
                    $ICCID: ICCIDAddInput
                    $IMSI: IMSIAddInput
                ) {
                    stixCyberObservableAdd(
                        type: $type,
                        stix_id: $stix_id,
                        x_opencti_score: $x_opencti_score,
                        x_opencti_description: $x_opencti_description,
                        createIndicator: $createIndicator,
                        createdBy: $createdBy,
                        objectMarking: $objectMarking,
                        objectLabel: $objectLabel,
                        update: $update,
                        externalReferences: $externalReferences,
                        objectOrganization: $objectOrganization,
                        AutonomousSystem: $AutonomousSystem,
                        Directory: $Directory,
                        DomainName: $DomainName,
                        EmailAddr: $EmailAddr,
                        EmailMessage: $EmailMessage,
                        EmailMimePartType: $EmailMimePartType,
                        Artifact: $Artifact,
                        StixFile: $StixFile,
                        X509Certificate: $X509Certificate,
                        IPv4Addr: $IPv4Addr,
                        IPv6Addr: $IPv6Addr,
                        MacAddr: $MacAddr,
                        Mutex: $Mutex,
                        NetworkTraffic: $NetworkTraffic,
                        Process: $Process,
                        Software: $Software,
                        Url: $Url,
                        UserAccount: $UserAccount,
                        WindowsRegistryKey: $WindowsRegistryKey,
                        WindowsRegistryValueType: $WindowsRegistryValueType,
                        CryptographicKey: $CryptographicKey,
                        CryptocurrencyWallet: $CryptocurrencyWallet,
                        Hostname: $Hostname,
                        Text: $Text,
                        UserAgent: $UserAgent
                        BankAccount: $BankAccount
                        PhoneNumber: $PhoneNumber
                        Credential: $Credential
                        TrackingNumber: $TrackingNumber
                        PaymentCard: $PaymentCard
                        Persona: $Persona
                        MediaContent: $MediaContent
                        SSHKey: $SSHKey
                        IMEI: $IMEI
                        ICCID: $ICCID
                        IMSI: $IMSI
                    ) {
                        id
                        standard_id
                        entity_type
                        parent_types
                        indicators {
                            edges {
                                node {
                                    id
                                    pattern
                                    pattern_type
                                }
                            }
                        }
                    }
                }
            """
            if type == "Autonomous-System":
                input_variables["AutonomousSystem"] = {
                    "number": observable_data["number"],
                    "name": (
                        observable_data["name"] if "name" in observable_data else None
                    ),
                    "rir": observable_data["rir"] if "rir" in observable_data else None,
                }
            elif type == "Directory":
                input_variables["Directory"] = {
                    "path": observable_data["path"],
                    "path_enc": (
                        observable_data["path_enc"]
                        if "path_enc" in observable_data
                        else None
                    ),
                    "ctime": (
                        observable_data["ctime"] if "ctime" in observable_data else None
                    ),
                    "mtime": (
                        observable_data["mtime"] if "mtime" in observable_data else None
                    ),
                    "atime": (
                        observable_data["atime"] if "atime" in observable_data else None
                    ),
                }
            elif type == "Domain-Name":
                input_variables["DomainName"] = {"value": observable_data["value"]}
                if attribute is not None:
                    input_variables["DomainName"][attribute] = simple_observable_value
            elif type == "Email-Addr":
                input_variables["EmailAddr"] = {
                    "value": observable_data["value"],
                    "display_name": (
                        observable_data["display_name"]
                        if "display_name" in observable_data
                        else None
                    ),
                }
            elif type == "Email-Message":
                input_variables["EmailMessage"] = {
                    "is_multipart": (
                        observable_data["is_multipart"]
                        if "is_multipart" in observable_data
                        else None
                    ),
                    "attribute_date": (
                        observable_data["date"] if "date" in observable_data else None
                    ),
                    "message_id": (
                        observable_data["message_id"]
                        if "message_id" in observable_data
                        else None
                    ),
                    "subject": (
                        observable_data["subject"]
                        if "subject" in observable_data
                        else None
                    ),
                    "received_lines": (
                        observable_data["received_lines"]
                        if "received_lines" in observable_data
                        else None
                    ),
                    "body": (
                        observable_data["body"] if "body" in observable_data else None
                    ),
                }
            elif type == "Email-Mime-Part-Type":
                input_variables["EmailMimePartType"] = {
                    "body": (
                        observable_data["body"] if "body" in observable_data else None
                    ),
                    "content_type": (
                        observable_data["content_type"]
                        if "content_type" in observable_data
                        else None
                    ),
                    "content_disposition": (
                        observable_data["content_disposition"]
                        if "content_disposition" in observable_data
                        else None
                    ),
                }
            elif type == "Artifact":
                if (
                    "x_opencti_additional_names" not in observable_data
                    and self.opencti.get_attribute_in_extension(
                        "additional_names", observable_data
                    )
                    is not None
                ):
                    observable_data["x_opencti_additional_names"] = (
                        self.opencti.get_attribute_in_extension(
                            "additional_names", observable_data
                        )
                    )
                input_variables["Artifact"] = {
                    "hashes": hashes if len(hashes) > 0 else None,
                    "mime_type": (
                        observable_data["mime_type"]
                        if "mime_type" in observable_data
                        else None
                    ),
                    "url": observable_data["url"] if "url" in observable_data else None,
                    "encryption_algorithm": (
                        observable_data["encryption_algorithm"]
                        if "encryption_algorithm" in observable_data
                        else None
                    ),
                    "decryption_key": (
                        observable_data["decryption_key"]
                        if "decryption_key" in observable_data
                        else None
                    ),
                    "x_opencti_additional_names": (
                        observable_data["x_opencti_additional_names"]
                        if "x_opencti_additional_names" in observable_data
                        else None
                    ),
                }
            elif type == "StixFile":
                if (
                    "x_opencti_additional_names" not in observable_data
                    and self.opencti.get_attribute_in_extension(
                        "additional_names", observable_data
                    )
                    is not None
                ):
                    observable_data["x_opencti_additional_names"] = (
                        self.opencti.get_attribute_in_extension(
                            "additional_names", observable_data
                        )
                    )
                input_variables["StixFile"] = {
                    "hashes": hashes if len(hashes) > 0 else None,
                    "size": (
                        observable_data["size"] if "size" in observable_data else None
                    ),
                    "name": (
                        observable_data["name"] if "name" in observable_data else None
                    ),
                    "name_enc": (
                        observable_data["name_enc"]
                        if "name_enc" in observable_data
                        else None
                    ),
                    "magic_number_hex": (
                        observable_data["magic_number_hex"]
                        if "magic_number_hex" in observable_data
                        else None
                    ),
                    "mime_type": (
                        observable_data["mime_type"]
                        if "mime_type" in observable_data
                        else None
                    ),
                    "mtime": (
                        observable_data["mtime"] if "mtime" in observable_data else None
                    ),
                    "ctime": (
                        observable_data["ctime"] if "ctime" in observable_data else None
                    ),
                    "atime": (
                        observable_data["atime"] if "atime" in observable_data else None
                    ),
                    "x_opencti_additional_names": (
                        observable_data["x_opencti_additional_names"]
                        if "x_opencti_additional_names" in observable_data
                        else None
                    ),
                }
            elif type == "X509-Certificate":
                input_variables["X509Certificate"] = {
                    "hashes": hashes if len(hashes) > 0 else None,
                    "is_self_signed": (
                        observable_data["is_self_signed"]
                        if "is_self_signed" in observable_data
                        else False
                    ),
                    "version": (
                        observable_data["version"]
                        if "version" in observable_data
                        else None
                    ),
                    "serial_number": (
                        observable_data["serial_number"]
                        if "serial_number" in observable_data
                        else None
                    ),
                    "signature_algorithm": (
                        observable_data["signature_algorithm"]
                        if "signature_algorithm" in observable_data
                        else None
                    ),
                    "issuer": (
                        observable_data["issuer"]
                        if "issuer" in observable_data
                        else None
                    ),
                    "validity_not_before": (
                        observable_data["validity_not_before"]
                        if "validity_not_before" in observable_data
                        else None
                    ),
                    "validity_not_after": (
                        observable_data["validity_not_after"]
                        if "validity_not_after" in observable_data
                        else None
                    ),
                    "subject": (
                        observable_data["subject"]
                        if "subject" in observable_data
                        else None
                    ),
                    "subject_public_key_algorithm": (
                        observable_data["subject_public_key_algorithm"]
                        if "subject_public_key_algorithm" in observable_data
                        else None
                    ),
                    "subject_public_key_modulus": (
                        observable_data["subject_public_key_modulus"]
                        if "subject_public_key_modulus" in observable_data
                        else None
                    ),
                    "subject_public_key_exponent": (
                        observable_data["subject_public_key_exponent"]
                        if "subject_public_key_exponent" in observable_data
                        else None
                    ),
                    "basic_constraints": (
                        observable_data["basic_constraints"]
                        if "basic_constraints" in observable_data
                        else None
                    ),
                    "name_constraints": (
                        observable_data["name_constraints"]
                        if "name_constraints" in observable_data
                        else None
                    ),
                    "policy_constraints": (
                        observable_data["policy_constraints"]
                        if "policy_constraints" in observable_data
                        else None
                    ),
                    "key_usage": (
                        observable_data["key_usage"]
                        if "key_usage" in observable_data
                        else None
                    ),
                    "extended_key_usage": (
                        observable_data["extended_key_usage"]
                        if "extended_key_usage" in observable_data
                        else None
                    ),
                    "subject_key_identifier": (
                        observable_data["subject_key_identifier"]
                        if "subject_key_identifier" in observable_data
                        else None
                    ),
                    "authority_key_identifier": (
                        observable_data["authority_key_identifier"]
                        if "authority_key_identifier" in observable_data
                        else None
                    ),
                    "subject_alternative_name": (
                        observable_data["subject_alternative_name"]
                        if "subject_alternative_name" in observable_data
                        else None
                    ),
                    "issuer_alternative_name": (
                        observable_data["issuer_alternative_name"]
                        if "issuer_alternative_name" in observable_data
                        else None
                    ),
                    "subject_directory_attributes": (
                        observable_data["subject_directory_attributes"]
                        if "subject_directory_attributes" in observable_data
                        else None
                    ),
                    "crl_distribution_points": (
                        observable_data["crl_distribution_points"]
                        if "crl_distribution_points" in observable_data
                        else None
                    ),
                    "inhibit_any_policy": (
                        observable_data["inhibit_any_policy"]
                        if "inhibit_any_policy" in observable_data
                        else None
                    ),
                    "private_key_usage_period_not_before": (
                        observable_data["private_key_usage_period_not_before"]
                        if "private_key_usage_period_not_before" in observable_data
                        else None
                    ),
                    "private_key_usage_period_not_after": (
                        observable_data["private_key_usage_period_not_after"]
                        if "private_key_usage_period_not_after" in observable_data
                        else None
                    ),
                    "certificate_policies": (
                        observable_data["certificate_policies"]
                        if "certificate_policies" in observable_data
                        else None
                    ),
                    "policy_mappings": (
                        observable_data["policy_mappings"]
                        if "policy_mappings" in observable_data
                        else None
                    ),
                }
            elif type == "SSH-Key" or type.lower() == "ssh-key":
                input_variables["SSHKey"] = {
                    "key_type": (
                        observable_data["key_type"]
                        if "key_type" in observable_data
                        else None
                    ),
                    "public_key": (
                        observable_data["public_key"]
                        if "public_key" in observable_data
                        else None
                    ),
                    "fingerprint_sha256": (
                        observable_data["fingerprint_sha256"]
                        if "fingerprint_sha256" in observable_data
                        else False
                    ),
                    "fingerprint_md5": (
                        observable_data["fingerprint_md5"]
                        if "fingerprint_md5" in observable_data
                        else None
                    ),
                    "key_length": (
                        observable_data["key_length"]
                        if "key_length" in observable_data
                        else None
                    ),
                    "comment": (
                        observable_data["comment"]
                        if "comment" in observable_data
                        else None
                    ),
                    "created": (
                        observable_data["created"]
                        if "created" in observable_data
                        else None
                    ),
                    "expiration_date": (
                        observable_data["expiration_date"]
                        if "expiration_date" in observable_data
                        else None
                    ),
                }
            elif type == "IPv4-Addr":
                input_variables["IPv4Addr"] = {
                    "value": (
                        observable_data["value"] if "value" in observable_data else None
                    ),
                }
            elif type == "IPv6-Addr":
                input_variables["IPv6Addr"] = {
                    "value": (
                        observable_data["value"] if "value" in observable_data else None
                    ),
                }
            elif type == "Mac-Addr":
                input_variables["MacAddr"] = {
                    "value": (
                        observable_data["value"] if "value" in observable_data else None
                    ),
                }
            elif type == "Mutex":
                input_variables["Mutex"] = {
                    "name": (
                        observable_data["name"] if "name" in observable_data else None
                    ),
                }
            elif type == "Network-Traffic":
                input_variables["NetworkTraffic"] = {
                    "start": (
                        observable_data["start"] if "start" in observable_data else None
                    ),
                    "end": observable_data["end"] if "end" in observable_data else None,
                    "is_active": (
                        observable_data["is_active"]
                        if "is_active" in observable_data
                        else None
                    ),
                    "src_port": (
                        observable_data["src_port"]
                        if "src_port" in observable_data
                        else None
                    ),
                    "dst_port": (
                        observable_data["dst_port"]
                        if "dst_port" in observable_data
                        else None
                    ),
                    "networkSrc": (
                        observable_data["src_ref"]
                        if "src_ref" in observable_data
                        else None
                    ),
                    "networkDst": (
                        observable_data["dst_ref"]
                        if "dst_ref" in observable_data
                        else None
                    ),
                    "protocols": (
                        observable_data["protocols"]
                        if "protocols" in observable_data
                        else None
                    ),
                    "src_byte_count": (
                        observable_data["src_byte_count"]
                        if "src_byte_count" in observable_data
                        else None
                    ),
                    "dst_byte_count": (
                        observable_data["dst_byte_count"]
                        if "dst_byte_count" in observable_data
                        else None
                    ),
                    "src_packets": (
                        observable_data["src_packets"]
                        if "src_packets" in observable_data
                        else None
                    ),
                    "dst_packets": (
                        observable_data["dst_packets"]
                        if "dst_packets" in observable_data
                        else None
                    ),
                }
            elif type == "Process":
                input_variables["Process"] = {
                    "is_hidden": (
                        observable_data["is_hidden"]
                        if "is_hidden" in observable_data
                        else None
                    ),
                    "pid": observable_data["pid"] if "pid" in observable_data else None,
                    "created_time": (
                        observable_data["created_time"]
                        if "created_time" in observable_data
                        else None
                    ),
                    "cwd": observable_data["cwd"] if "cwd" in observable_data else None,
                    "command_line": (
                        observable_data["command_line"]
                        if "command_line" in observable_data
                        else None
                    ),
                    "environment_variables": (
                        observable_data["environment_variables"]
                        if "environment_variables" in observable_data
                        else None
                    ),
                }
            elif type == "Software":
                if (
                    "x_opencti_product" not in observable_data
                    and self.opencti.get_attribute_in_extension(
                        "x_opencti_product", observable_data
                    )
                    is not None
                ):
                    observable_data["x_opencti_product"] = (
                        self.opencti.get_attribute_in_extension(
                            "x_opencti_product", observable_data
                        )
                    )
                input_variables["Software"] = {
                    "name": (
                        observable_data["name"] if "name" in observable_data else None
                    ),
                    "cpe": observable_data["cpe"] if "cpe" in observable_data else None,
                    "swid": (
                        observable_data["swid"] if "swid" in observable_data else None
                    ),
                    "languages": (
                        observable_data["languages"]
                        if "languages" in observable_data
                        else None
                    ),
                    "vendor": (
                        observable_data["vendor"]
                        if "vendor" in observable_data
                        else None
                    ),
                    "version": (
                        observable_data["version"]
                        if "version" in observable_data
                        else None
                    ),
                    "x_opencti_product": (
                        observable_data["x_opencti_product"]
                        if "x_opencti_product" in observable_data
                        else None
                    ),
                }
            elif type == "Url":
                input_variables["Url"] = {
                    "value": (
                        observable_data["value"] if "value" in observable_data else None
                    ),
                }
            elif type == "User-Account":
                input_variables["UserAccount"] = {
                    "user_id": (
                        observable_data["user_id"]
                        if "user_id" in observable_data
                        else None
                    ),
                    "credential": (
                        observable_data["credential"]
                        if "credential" in observable_data
                        else None
                    ),
                    "account_login": (
                        observable_data["account_login"]
                        if "account_login" in observable_data
                        else None
                    ),
                    "account_type": (
                        observable_data["account_type"]
                        if "account_type" in observable_data
                        else None
                    ),
                    "display_name": (
                        observable_data["display_name"]
                        if "display_name" in observable_data
                        else None
                    ),
                    "is_service_account": (
                        observable_data["is_service_account"]
                        if "is_service_account" in observable_data
                        else None
                    ),
                    "is_privileged": (
                        observable_data["is_privileged"]
                        if "is_privileged" in observable_data
                        else None
                    ),
                    "can_escalate_privs": (
                        observable_data["can_escalate_privs"]
                        if "can_escalate_privs" in observable_data
                        else None
                    ),
                    "is_disabled": (
                        observable_data["is_disabled"]
                        if "is_disabled" in observable_data
                        else None
                    ),
                    "account_created": (
                        observable_data["account_created"]
                        if "account_created" in observable_data
                        else None
                    ),
                    "account_expires": (
                        observable_data["account_expires"]
                        if "account_expires" in observable_data
                        else None
                    ),
                    "credential_last_changed": (
                        observable_data["credential_last_changed"]
                        if "credential_last_changed" in observable_data
                        else None
                    ),
                    "account_first_login": (
                        observable_data["account_first_login"]
                        if "account_first_login" in observable_data
                        else None
                    ),
                    "account_last_login": (
                        observable_data["account_last_login"]
                        if "account_last_login" in observable_data
                        else None
                    ),
                }
            elif type == "Windows-Registry-Key":
                input_variables["WindowsRegistryKey"] = {
                    "attribute_key": (
                        observable_data["key"] if "key" in observable_data else None
                    ),
                    "modified_time": (
                        observable_data["modified_time"]
                        if "modified_time" in observable_data
                        else None
                    ),
                    "number_of_subkeys": (
                        observable_data["number_of_subkeys"]
                        if "number_of_subkeys" in observable_data
                        else None
                    ),
                }
            elif type == "Windows-Registry-Value-Type":
                input_variables["WindowsRegistryValueType"] = {
                    "name": (
                        observable_data["name"] if "name" in observable_data else None
                    ),
                    "data": (
                        observable_data["data"] if "data" in observable_data else None
                    ),
                    "data_type": (
                        observable_data["data_type"]
                        if "data_type" in observable_data
                        else None
                    ),
                }
            elif type == "User-Agent":
                input_variables["UserAgent"] = {
                    "value": (
                        observable_data["value"] if "value" in observable_data else None
                    ),
                }
            elif type == "Cryptographic-Key":
                input_variables["CryptographicKey"] = {
                    "value": (
                        observable_data["value"] if "value" in observable_data else None
                    ),
                }
            elif type == "Hostname":
                input_variables["Hostname"] = {
                    "value": (
                        observable_data["value"] if "value" in observable_data else None
                    ),
                }
            elif type == "Text":
                input_variables["Text"] = {
                    "value": (
                        observable_data["value"] if "value" in observable_data else None
                    ),
                }
            elif type == "Bank-Account":
                input_variables["BankAccount"] = {
                    "iban": (
                        observable_data["iban"] if "iban" in observable_data else None
                    ),
                    "bic": observable_data["bic"] if "bic" in observable_data else None,
                    "account_number": (
                        observable_data["account_number"]
                        if "account_number" in observable_data
                        else None
                    ),
                }
            elif type == "Phone-Number":
                input_variables["PhoneNumber"] = {
                    "value": (
                        observable_data["value"] if "value" in observable_data else None
                    ),
                }
            elif type == "Payment-Card":
                input_variables["PaymentCard"] = {
                    "card_number": (
                        observable_data["card_number"]
                        if "card_number" in observable_data
                        else None
                    ),
                    "expiration_date": (
                        observable_data["expiration_date"]
                        if "expiration_date" in observable_data
                        else None
                    ),
                    "cvv": observable_data["cvv"] if "cvv" in observable_data else None,
                    "holder_name": (
                        observable_data["holder_name"]
                        if "holder_name" in observable_data
                        else None
                    ),
                }
            elif type == "Media-Content":
                input_variables["MediaContent"] = {
                    "title": (
                        observable_data["title"] if "title" in observable_data else None
                    ),
                    "content": (
                        observable_data["content"]
                        if "content" in observable_data
                        else None
                    ),
                    "media_category": (
                        observable_data["media_category"]
                        if "media_category" in observable_data
                        else None
                    ),
                    "url": observable_data["url"] if "url" in observable_data else None,
                    "publication_date": (
                        observable_data["publication_date"]
                        if "publication_date" in observable_data
                        else None
                    ),
                }
            elif type == "Persona":
                input_variables["Persona"] = {
                    "persona_name": (
                        observable_data["persona_name"]
                        if "persona_name" in observable_data
                        else None
                    ),
                    "persona_type": (
                        observable_data["persona_type"]
                        if "persona_type" in observable_data
                        else None
                    ),
                }
            elif type == "Payment-Card" or type.lower() == "x-opencti-payment-card":
                input_variables["PaymentCard"] = {
                    "card_number": (
                        observable_data["card_number"]
                        if "card_number" in observable_data
                        else None
                    ),
                    "expiration_date": (
                        observable_data["expiration_date"]
                        if "expiration_date" in observable_data
                        else None
                    ),
                    "cvv": observable_data["cvv"] if "cvv" in observable_data else None,
                    "holder_name": (
                        observable_data["holder_name"]
                        if "holder_name" in observable_data
                        else None
                    ),
                }
            elif (
                type == "Cryptocurrency-Wallet"
                or type.lower() == "x-opencti-cryptocurrency-wallet"
            ):
                input_variables["CryptocurrencyWallet"] = {
                    "value": (
                        observable_data["value"] if "value" in observable_data else None
                    ),
                }
            elif type == "Credential" or type.lower() == "x-opencti-credential":
                input_variables["Credential"] = {
                    "value": (
                        observable_data["value"] if "value" in observable_data else None
                    ),
                }
            elif (
                type == "Tracking-Number" or type.lower() == "x-opencti-tracking-number"
            ):
                input_variables["TrackingNumber"] = {
                    "value": (
                        observable_data["value"] if "value" in observable_data else None
                    ),
                }
            elif type == "IMEI" or type.lower() == "x-opencti-imei":
                input_variables["IMEI"] = {
                    "value": (
                        observable_data["value"] if "value" in observable_data else None
                    ),
                }
            elif type == "ICCID" or type.lower() == "x-opencti-iccid":
                input_variables["ICCID"] = {
                    "value": (
                        observable_data["value"] if "value" in observable_data else None
                    ),
                }
            elif type == "IMSI" or type.lower() == "x-opencti-imsi":
                input_variables["IMSI"] = {
                    "value": (
                        observable_data["value"] if "value" in observable_data else None
                    ),
                }
            result = self.opencti.query(query, input_variables)
            if "payload_bin" in observable_data and "mime_type" in observable_data:
                self.add_file(
                    id=result["data"]["stixCyberObservableAdd"]["id"],
                    file_name=(
                        observable_data["x_opencti_additional_names"][0]
                        if "x_opencti_additional_names" in observable_data
                        and len(observable_data["x_opencti_additional_names"]) > 0
                        else "artifact.bin"
                    ),
                    data=base64.b64decode(observable_data["payload_bin"]),
                    mime_type=observable_data["mime_type"],
                )
            return self.opencti.process_multiple_fields(
                result["data"]["stixCyberObservableAdd"]
            )
        else:
            self.opencti.app_logger.error("Missing parameters: type")

    """
        Upload an artifact

        :param file_path: the file path
        :return Stix-Observable object
    """

    def upload_artifact(self, **kwargs):
        file_name = kwargs.get("file_name", None)
        data = kwargs.get("data", None)
        mime_type = kwargs.get("mime_type", "text/plain")
        x_opencti_description = kwargs.get("x_opencti_description", False)
        created_by = kwargs.get("createdBy", None)
        object_marking = kwargs.get("objectMarking", None)
        object_label = kwargs.get("objectLabel", None)
        create_indicator = kwargs.get("createIndicator", False)

        if file_name is not None and mime_type is not None:
            final_file_name = os.path.basename(file_name)
            self.opencti.app_logger.info(
                "Creating Stix-Cyber-Observable {artifact} with indicator",
                {"create_indicator": create_indicator},
            )
            query = """
                mutation ArtifactImport($file: Upload!, $x_opencti_description: String, $createdBy: String, $objectMarking: [String], $objectLabel: [String]) {
                    artifactImport(file: $file, x_opencti_description: $x_opencti_description, createdBy: $createdBy, objectMarking: $objectMarking, objectLabel: $objectLabel) {
                        id
                        standard_id
                        entity_type
                        parent_types
                        spec_version
                        created_at
                        updated_at
                        createdBy {
                            ... on Identity {
                                id
                                standard_id
                                entity_type
                                parent_types
                                spec_version
                                name
                                description
                                roles
                                contact_information
                                x_opencti_aliases
                                created
                                modified
                                objectLabel {
                                    id
                                    value
                                    color
                                }
                            }
                            ... on Organization {
                                x_opencti_organization_type
                                x_opencti_reliability
                            }
                            ... on Individual {
                                x_opencti_firstname
                                x_opencti_lastname
                            }
                        }
                        objectMarking {
                            id
                            standard_id
                            entity_type
                            definition_type
                            definition
                            created
                            modified
                            x_opencti_order
                            x_opencti_color
                        }
                        objectLabel {
                            id
                            value
                            color
                        }
                        externalReferences {
                            edges {
                                node {
                                    id
                                    standard_id
                                    entity_type
                                    source_name
                                    description
                                    url
                                    hash
                                    external_id
                                    created
                                    modified
                                }
                            }
                        }
                        observable_value
                        x_opencti_description
                        x_opencti_score
                        indicators {
                            edges {
                                node {
                                    id
                                    pattern
                                    pattern_type
                                }
                            }
                        }
                        mime_type
                        payload_bin
                        url
                        encryption_algorithm
                        decryption_key
                        hashes {
                            algorithm
                            hash
                        }
                        importFiles {
                            edges {
                                node {
                                    id
                                    name
                                    size
                                }
                            }
                        }
                    }
                }
            """
            if data is None:
                data = open(file_name, "rb")
                if file_name.endswith(".json"):
                    mime_type = "application/json"
                else:
                    mime_type = magic.from_file(file_name, mime=True)

            result = self.opencti.query(
                query,
                {
                    "file": (self.file(final_file_name, data, mime_type)),
                    "x_opencti_description": x_opencti_description,
                    "createdBy": created_by,
                    "objectMarking": object_marking,
                    "objectLabel": object_label,
                },
            )
            return self.opencti.process_multiple_fields(
                result["data"]["artifactImport"]
            )
        else:
            self.opencti.app_logger.error("Missing parameters: type")

    """
        Update a Stix-Observable object field

        :param id: the Stix-Observable id
        :param input: the input of the field
        :return The updated Stix-Observable object
    """

    def update_field(self, **kwargs):
        id = kwargs.get("id", None)
        input = kwargs.get("input", None)
        if id is not None and input is not None:
            self.opencti.app_logger.info("Updating Stix-Observable", {"id": id})
            query = """
                mutation StixCyberObservableEdit($id: ID!, $input: [EditInput]!) {
                    stixCyberObservableEdit(id: $id) {
                        fieldPatch(input: $input) {
                            id
                            standard_id
                            entity_type
                        }
                    }
                }
            """
            result = self.opencti.query(
                query,
                {
                    "id": id,
                    "input": input,
                },
            )
            return self.opencti.process_multiple_fields(
                result["data"]["stixCyberObservableEdit"]["fieldPatch"]
            )
        else:
            self.opencti.app_logger.error(
                "[opencti_stix_cyber_observable_update_field] Missing parameters: id and input",
            )
            return None

    """
        Promote a Stix-Observable to an Indicator

        :param id: the Stix-Observable id
        :return the newly created indicator
    """

    def promote_to_indicator_v2(self, **kwargs):
        id = kwargs.get("id", None)
        custom_attributes = kwargs.get("customAttributes", None)
        if id is not None:
            self.opencti.app_logger.info("Promoting Stix-Observable", {"id": id})
            query = (
                """
                        mutation StixCyberObservableEdit($id: ID!) {
                            stixCyberObservableEdit(id: $id) {
                                promoteToIndicator {
                                    """
                + (
                    custom_attributes
                    if custom_attributes is not None
                    else (INDICATOR_PROPERTIES)
                )
                + """
                            }
                        }
                    }
             """
            )
            result = self.opencti.query(query, {"id": id})
            return self.opencti.process_multiple_fields(
                result["data"]["stixCyberObservableEdit"]["promoteToIndicator"]
            )
        else:
            self.opencti.app_logger.error(
                "[opencti_stix_cyber_observable_promote] Missing parameters: id"
            )
            return None

    """
        Delete a Stix-Observable

        :param id: the Stix-Observable id
        :return void
    """

    def delete(self, **kwargs):
        id = kwargs.get("id", None)
        if id is not None:
            self.opencti.app_logger.info("Deleting Stix-Observable", {"id": id})
            query = """
                 mutation StixCyberObservableEdit($id: ID!) {
                     stixCyberObservableEdit(id: $id) {
                         delete
                     }
                 }
             """
            self.opencti.query(query, {"id": id})
        else:
            self.opencti.app_logger.error(
                "[opencti_stix_cyber_observable_delete] Missing parameters: id"
            )
            return None

    """
        Update the Identity author of a Stix-Cyber-Observable object (created_by)

        :param id: the id of the Stix-Cyber-Observable
        :param identity_id: the id of the Identity
        :return Boolean
    """

    def update_created_by(self, **kwargs):
        id = kwargs.get("id", None)
        identity_id = kwargs.get("identity_id", None)
        if id is not None:
            self.opencti.app_logger.info(
                "Updating author of Stix-Cyber-Observable with Identity",
                {"id": id, "identity_id": identity_id},
            )
            custom_attributes = """
                id
                createdBy {
                    ... on Identity {
                        id
                        standard_id
                        entity_type
                        parent_types
                        name
                        x_opencti_aliases
                        description
                        created
                        modified
                    }
                    ... on Organization {
                        x_opencti_organization_type
                        x_opencti_reliability
                    }
                    ... on Individual {
                        x_opencti_firstname
                        x_opencti_lastname
                    }
                }
            """
            stix_domain_object = self.read(id=id, customAttributes=custom_attributes)
            if stix_domain_object["createdBy"] is not None:
                query = """
                    mutation StixCyberObservableEdit($id: ID!, $toId: StixRef! $relationship_type: String!) {
                        stixCyberObservableEdit(id: $id) {
                            relationDelete(toId: $toId, relationship_type: $relationship_type) {
                                id
                            }
                        }
                    }
                """
                self.opencti.query(
                    query,
                    {
                        "id": id,
                        "toId": stix_domain_object["createdBy"]["id"],
                        "relationship_type": "created-by",
                    },
                )
            if identity_id is not None:
                # Add the new relation
                query = """
                    mutation StixCyberObservableEdit($id: ID!, $input: StixRefRelationshipAddInput!) {
                        stixCyberObservableEdit(id: $id) {
                            relationAdd(input: $input) {
                                id
                            }
                        }
                    }
               """
                variables = {
                    "id": id,
                    "input": {
                        "toId": identity_id,
                        "relationship_type": "created-by",
                    },
                }
                self.opencti.query(query, variables)
        else:
            self.opencti.app_logger.error("Missing parameters: id")
            return False

    """
        Add a Marking-Definition object to Stix-Cyber-Observable object (object_marking_refs)

        :param id: the id of the Stix-Cyber-Observable
        :param marking_definition_id: the id of the Marking-Definition
        :return Boolean
    """

    def add_marking_definition(self, **kwargs):
        id = kwargs.get("id", None)
        marking_definition_id = kwargs.get("marking_definition_id", None)
        if id is not None and marking_definition_id is not None:
            custom_attributes = """
                id
                objectMarking {
                    standard_id
                    entity_type
                    definition_type
                    definition
                    x_opencti_order
                    x_opencti_color
                    created
                    modified
                }
            """
            stix_cyber_observable = self.read(id=id, customAttributes=custom_attributes)
            if stix_cyber_observable is None:
                self.opencti.app_logger.error(
                    "Cannot add Marking-Definition, entity not found"
                )
                return False
            if marking_definition_id in stix_cyber_observable["objectMarkingIds"]:
                return True
            else:
                self.opencti.app_logger.info(
                    "Adding Marking-Definition to Stix-Cyber-Observable",
                    {"marking_definition_id": marking_definition_id, "id": id},
                )
                query = """
                   mutation StixCyberObservableAddRelation($id: ID!, $input: StixRefRelationshipAddInput!) {
                       stixCyberObservableEdit(id: $id) {
                            relationAdd(input: $input) {
                                id
                            }
                       }
                   }
                """
                self.opencti.query(
                    query,
                    {
                        "id": id,
                        "input": {
                            "toId": marking_definition_id,
                            "relationship_type": "object-marking",
                        },
                    },
                )
                return True
        else:
            self.opencti.app_logger.error(
                "Missing parameters: id and marking_definition_id"
            )
            return False

    """
        Remove a Marking-Definition object to Stix-Cyber-Observable object

        :param id: the id of the Stix-Cyber-Observable
        :param marking_definition_id: the id of the Marking-Definition
        :return Boolean
    """

    def remove_marking_definition(self, **kwargs):
        id = kwargs.get("id", None)
        marking_definition_id = kwargs.get("marking_definition_id", None)
        if id is not None and marking_definition_id is not None:
            self.opencti.app_logger.info(
                "Removing Marking-Definition from Stix-Cyber-Observable",
                {"marking_definition_id": marking_definition_id, "id": id},
            )
            query = """
               mutation StixCyberObservableRemoveRelation($id: ID!, $toId: StixRef!, $relationship_type: String!) {
                   stixCyberObservableEdit(id: $id) {
                        relationDelete(toId: $toId, relationship_type: $relationship_type) {
                            id
                        }
                   }
               }
            """
            self.opencti.query(
                query,
                {
                    "id": id,
                    "toId": marking_definition_id,
                    "relationship_type": "object-marking",
                },
            )
            return True
        else:
            self.opencti.app_logger.error("Missing parameters: id and label_id")
            return False

    """
        Add a Label object to Stix-Cyber-Observable object

        :param id: the id of the Stix-Cyber-Observable
        :param label_id: the id of the Label
        :return Boolean
    """

    def add_label(self, **kwargs):
        id = kwargs.get("id", None)
        label_id = kwargs.get("label_id", None)
        label_name = kwargs.get("label_name", None)
        if label_name is not None:
            label = self.opencti.label.read(
                filters={
                    "mode": "and",
                    "filters": [{"key": "value", "values": [label_name]}],
                    "filterGroups": [],
                }
            )
            if label:
                label_id = label["id"]
            else:
                label = self.opencti.label.create(value=label_name)
                label_id = label["id"]
        if id is not None and label_id is not None:
            self.opencti.app_logger.info(
                "Adding label to Stix-Cyber-Observable",
                {"label_id": label_id, "id": id},
            )
            query = """
               mutation StixCyberObservableAddRelation($id: ID!, $input: StixRefRelationshipAddInput!) {
                   stixCyberObservableEdit(id: $id) {
                        relationAdd(input: $input) {
                            id
                        }
                   }
               }
            """
            self.opencti.query(
                query,
                {
                    "id": id,
                    "input": {
                        "toId": label_id,
                        "relationship_type": "object-label",
                    },
                },
            )
            return True
        else:
            self.opencti.app_logger.error("Missing parameters: id and label_id")
            return False

    """
        Remove a Label object to Stix-Cyber-Observable object

        :param id: the id of the Stix-Cyber-Observable
        :param label_id: the id of the Label
        :return Boolean
    """

    def remove_label(self, **kwargs):
        id = kwargs.get("id", None)
        label_id = kwargs.get("label_id", None)
        label_name = kwargs.get("label_name", None)
        if label_name is not None:
            label = self.opencti.label.read(
                filters={
                    "mode": "and",
                    "filters": [{"key": "value", "values": [label_name]}],
                    "filterGroups": [],
                }
            )
            if label:
                label_id = label["id"]
        if id is not None and label_id is not None:
            self.opencti.app_logger.info(
                "Removing label from Stix-Cyber-Observable",
                {"label_id": label_id, "id": id},
            )
            query = """
               mutation StixCyberObservableRemoveRelation($id: ID!, $toId: StixRef!, $relationship_type: String!) {
                   stixCyberObservableEdit(id: $id) {
                        relationDelete(toId: $toId, relationship_type: $relationship_type) {
                            id
                        }
                   }
               }
            """
            self.opencti.query(
                query,
                {
                    "id": id,
                    "toId": label_id,
                    "relationship_type": "object-label",
                },
            )
            return True
        else:
            self.opencti.app_logger.error("Missing parameters: id and label_id")
            return False

    """
        Add a External-Reference object to Stix-Cyber-Observable object (object_marking_refs)

        :param id: the id of the Stix-Cyber-Observable
        :param marking_definition_id: the id of the Marking-Definition
        :return Boolean
    """

    def add_external_reference(self, **kwargs):
        id = kwargs.get("id", None)
        external_reference_id = kwargs.get("external_reference_id", None)
        if id is not None and external_reference_id is not None:
            custom_attributes = """
                id
                externalReferences {
                    edges {
                        node {
                            id
                            standard_id
                            entity_type
                            source_name
                            description
                            url
                            hash
                            external_id
                            created
                            modified
                        }
                    }
                }
            """
            stix_domain_object = self.read(id=id, customAttributes=custom_attributes)
            if stix_domain_object is None:
                self.opencti.app_logger.error(
                    "Cannot add External-Reference, entity not found"
                )
                return False
            if external_reference_id in stix_domain_object["externalReferencesIds"]:
                return True
            else:
                self.opencti.app_logger.info(
                    "Adding External-Reference to Stix-Cyber-Observable",
                    {"external_reference_id": external_reference_id, "id": id},
                )
                query = """
                   mutation StixCyberObservabletEditRelationAdd($id: ID!, $input: StixRefRelationshipAddInput!) {
                       stixCyberObservableEdit(id: $id) {
                            relationAdd(input: $input) {
                                id
                            }
                       }
                   }
                """
                self.opencti.query(
                    query,
                    {
                        "id": id,
                        "input": {
                            "toId": external_reference_id,
                            "relationship_type": "external-reference",
                        },
                    },
                )
                return True
        else:
            self.opencti.app_logger.error(
                "Missing parameters: id and external_reference_id"
            )
            return False

    """
        Remove a Label object to Stix-Cyber-Observable object

        :param id: the id of the Stix-Cyber-Observable
        :param label_id: the id of the Label
        :return Boolean
    """

    def remove_external_reference(self, **kwargs):
        id = kwargs.get("id", None)
        external_reference_id = kwargs.get("external_reference_id", None)
        if id is not None and external_reference_id is not None:
            self.opencti.app_logger.info(
                "Removing External-Reference from Stix-Cyber-Observable",
                {"external_reference_id": external_reference_id, "id": id},
            )
            query = """
               mutation StixCyberObservableRemoveRelation($id: ID!, $toId: StixRef!, $relationship_type: String!) {
                   stixCyberObservableEdit(id: $id) {
                        relationDelete(toId: $toId, relationship_type: $relationship_type) {
                            id
                        }
                   }
               }
            """
            self.opencti.query(
                query,
                {
                    "id": id,
                    "toId": external_reference_id,
                    "relationship_type": "external-reference",
                },
            )
            return True
        else:
            self.opencti.app_logger.error("Missing parameters: id and label_id")
            return False

    def push_list_export(
        self,
        entity_id,
        entity_type,
        file_name,
        file_markings,
        data,
        list_filters="",
        mime_type=None,
    ):
        query = """
            mutation StixCyberObservablesExportPush(
                $entity_id: String,
                $entity_type: String!,
                $file: Upload!,
                $file_markings: [String]!,
                $listFilters: String
            ) {
                stixCyberObservablesExportPush(
                    entity_id: $entity_id,
                    entity_type: $entity_type,
                    file: $file,
                    file_markings: $file_markings,
                    listFilters: $listFilters
                )
            }
        """
        if mime_type is None:
            file = self.file(file_name, data)
        else:
            file = self.file(file_name, data, mime_type)
        self.opencti.query(
            query,
            {
                "entity_id": entity_id,
                "entity_type": entity_type,
                "file": file,
                "file_markings": file_markings,
                "listFilters": list_filters,
            },
        )

    def ask_for_enrichment(self, **kwargs) -> str:
        id = kwargs.get("id", None)
        connector_id = kwargs.get("connector_id", None)

        if id is None or connector_id is None:
            self.opencti.app_logger.error("Missing parameters: id and connector_id")
            return ""

        query = """
            mutation StixCoreObjectEnrichmentLinesMutation($id: ID!, $connectorId: ID!) {
                stixCoreObjectEdit(id: $id) {
                    askEnrichment(connectorId: $connectorId) {
                        id
                    }
                }
            }
            """

        result = self.opencti.query(
            query,
            {
                "id": id,
                "connectorId": connector_id,
            },
        )
        # return work_id
        return result["data"]["stixCoreObjectEdit"]["askEnrichment"]["id"]

    """
        Get the reports about a Stix-Cyber-Observable object

        :param id: the id of the Stix-Cyber-Observable
        :return List of reports
    """

    def reports(self, **kwargs):
        id = kwargs.get("id", None)
        if id is not None:
            self.opencti.app_logger.info(
                "Getting reports of the Stix-Cyber-Observable", {"id": id}
            )
            query = """
                query StixCyberObservable($id: String!) {
                    stixCyberObservable(id: $id) {
                        reports {
                            edges {
                                node {
                                    id
                                    standard_id
                                    entity_type
                                    parent_types
                                    spec_version
                                    created_at
                                    updated_at
                                    createdBy {
                                        ... on Identity {
                                            id
                                            standard_id
                                            entity_type
                                            parent_types
                                            spec_version
                                            identity_class
                                            name
                                            description
                                            roles
                                            contact_information
                                            x_opencti_aliases
                                            created
                                            modified
                                            objectLabel {
                                                id
                                                value
                                                color
                                            }
                                        }
                                        ... on Organization {
                                            x_opencti_organization_type
                                            x_opencti_reliability
                                        }
                                        ... on Individual {
                                            x_opencti_firstname
                                            x_opencti_lastname
                                        }
                                    }
                                    objectMarking {
                                        id
                                        standard_id
                                        entity_type
                                        definition_type
                                        definition
                                        created
                                        modified
                                        x_opencti_order
                                        x_opencti_color
                                    }
                                    objectLabel {
                                        id
                                        value
                                        color
                                    }
                                    externalReferences {
                                        edges {
                                            node {
                                                id
                                                standard_id
                                                entity_type
                                                source_name
                                                description
                                                url
                                                hash
                                                external_id
                                                created
                                                modified
                                                importFiles {
                                                    edges {
                                                        node {
                                                            id
                                                            name
                                                            size
                                                            metaData {
                                                                mimetype
                                                                version
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                    revoked
                                    confidence
                                    created
                                    modified
                                    name
                                    description
                                    report_types
                                    published
                                }
                            }
                        }
                    }
                }
             """
            result = self.opencti.query(query, {"id": id})
            processed_result = self.opencti.process_multiple_fields(
                result["data"]["stixCyberObservable"]
            )
            if processed_result:
                return processed_result["reports"]
            else:
                return []
        else:
            self.opencti.app_logger.error("Missing parameters: id")
            return None

    """
        Get the notes about a Stix-Cyber-Observable object

        :param id: the id of the Stix-Cyber-Observable
        :return List of notes
    """

    def notes(self, **kwargs):
        id = kwargs.get("id", None)
        if id is not None:
            self.opencti.app_logger.info(
                "Getting notes of the Stix-Cyber-Observable", {"id": id}
            )
            query = """
                query StixCyberObservable($id: String!) {
                    stixCyberObservable(id: $id) {
                        notes {
                            edges {
                                node {
                                    id
                                    standard_id
                                    entity_type
                                    parent_types
                                    spec_version
                                    created_at
                                    updated_at
                                    createdBy {
                                        ... on Identity {
                                            id
                                            standard_id
                                            entity_type
                                            parent_types
                                            spec_version
                                            identity_class
                                            name
                                            description
                                            roles
                                            contact_information
                                            x_opencti_aliases
                                            created
                                            modified
                                            objectLabel {
                                                id
                                                value
                                                color
                                            }
                                        }
                                        ... on Organization {
                                            x_opencti_organization_type
                                            x_opencti_reliability
                                        }
                                        ... on Individual {
                                            x_opencti_firstname
                                            x_opencti_lastname
                                        }
                                    }
                                    objectMarking {
                                        id
                                        standard_id
                                        entity_type
                                        definition_type
                                        definition
                                        created
                                        modified
                                        x_opencti_order
                                        x_opencti_color
                                    }
                                    objectLabel {
                                        id
                                        value
                                        color
                                    }
                                    externalReferences {
                                        edges {
                                            node {
                                                id
                                                standard_id
                                                entity_type
                                                source_name
                                                description
                                                url
                                                hash
                                                external_id
                                                created
                                                modified
                                                importFiles {
                                                    edges {
                                                        node {
                                                            id
                                                            name
                                                            size
                                                            metaData {
                                                                mimetype
                                                                version
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                    revoked
                                    confidence
                                    created
                                    modified
                                    attribute_abstract
                                    content
                                    authors
                                    note_types
                                    likelihood
                                }
                            }
                        }
                    }
                }
             """
            result = self.opencti.query(query, {"id": id})
            processed_result = self.opencti.process_multiple_fields(
                result["data"]["stixCyberObservable"]
            )
            if processed_result:
                return processed_result["notes"]
            else:
                return []
        else:
            self.opencti.app_logger.error("Missing parameters: id")
            return None

    """
        Get the observed data of a Stix-Cyber-Observable object

        :param id: the id of the Stix-Cyber-Observable
        :return List of observed data
    """

    def observed_data(self, **kwargs):
        id = kwargs.get("id", None)
        if id is not None:
            self.opencti.app_logger.info(
                "Getting Observed-Data of the Stix-Cyber-Observable", {"id": id}
            )
            query = """
                    query StixCyberObservable($id: String!) {
                        stixCyberObservable(id: $id) {
                            observedData {
                                edges {
                                    node {
                                        id
                                        standard_id
                                        entity_type
                                        parent_types
                                        spec_version
                                        created_at
                                        updated_at
                                        createdBy {
                                            ... on Identity {
                                                id
                                                standard_id
                                                entity_type
                                                parent_types
                                                spec_version
                                                identity_class
                                                name
                                                description
                                                roles
                                                contact_information
                                                x_opencti_aliases
                                                created
                                                modified
                                                objectLabel {
                                                    id
                                                    value
                                                    color
                                                }
                                            }
                                            ... on Organization {
                                                x_opencti_organization_type
                                                x_opencti_reliability
                                            }
                                            ... on Individual {
                                                x_opencti_firstname
                                                x_opencti_lastname
                                            }
                                        }
                                        objectMarking {
                                            id
                                            standard_id
                                            entity_type
                                            definition_type
                                            definition
                                            created
                                            modified
                                            x_opencti_order
                                            x_opencti_color
                                        }
                                        objectLabel {
                                            id
                                            value
                                            color
                                        }
                                        externalReferences {
                                            edges {
                                                node {
                                                    id
                                                    standard_id
                                                    entity_type
                                                    source_name
                                                    description
                                                    url
                                                    hash
                                                    external_id
                                                    created
                                                    modified
                                                    importFiles {
                                                        edges {
                                                            node {
                                                                id
                                                                name
                                                                size
                                                                metaData {
                                                                    mimetype
                                                                    version
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                        revoked
                                        confidence
                                        created
                                        modified
                                        first_observed
                                        last_observed
                                        number_observed
                                        importFiles {
                                            edges {
                                                node {
                                                    id
                                                    name
                                                    size
                                                    metaData {
                                                        mimetype
                                                        version
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                 """
            result = self.opencti.query(query, {"id": id})
            processed_result = self.opencti.process_multiple_fields(
                result["data"]["stixCyberObservable"]
            )
            if processed_result:
                return processed_result["observedData"]
            else:
                return []
        else:
            self.opencti.app_logger.error("Missing parameters: id")
            return None
