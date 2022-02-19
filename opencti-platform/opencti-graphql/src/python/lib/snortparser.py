import collections
import ipaddress
import re
from typing import Any, Dict, List, Optional, Tuple

try:
    from .dicts import Dicts
except ImportError:
    from dicts import Dicts


class Parser:
    """
    this will take an array of lines and parse it and hand
    back a dictionary
    NOTE: if you pass an invalid rule to the parser,
    it will a raise ValueError.
    """

    def __init__(self, rule):
        self.dicts = Dicts()
        self.rule = rule
        self.header = self.parse_header()
        self.options = self.parse_options()
        self.validate_options(self.options)
        self.data = {"header": self.header, "options": self.options}
        self.all = self.data

    def __iter__(self):
        yield self.data

    def __getitem__(self, key):
        if key == "all":
            return self.data
        return self.data[key]

    @staticmethod
    def actions(action: str) -> str:
        actions = {
            "alert",
            "log",
            "pass",
            "activate",
            "dynamic",
            "drop",
            "reject",
            "sdrop",
        }

        if action in actions:
            return action
        msg = f"Invalid action specified {action}"
        raise ValueError(msg)

    @staticmethod
    def proto(proto: str) -> str:
        protos = {"tcp", "udp", "icmp", "ip"}

        if proto.lower() in protos:
            return proto
        msg = f"Unsupported Protocol {proto} "
        raise ValueError(msg)

    @staticmethod
    def __ip_to_tuple(ip: str) -> Tuple[bool, str]:
        if ip.startswith("!"):
            ip = ip.lstrip("!")
            return False, ip
        return True, ip

    def __form_ip_list(self, ip_list: str) -> List[Tuple[bool, str]]:
        return [self.__ip_to_tuple(ip) for ip in ip_list.split(",")]

    def __flatten_ip(self, ip):
        list_deny = True
        if ip.startswith("!"):
            list_deny = False
            ip = ip.lstrip("!")
        _ip_list = []
        _not_nest = True
        ip = re.sub(r"^\[|\]$", "", ip)
        ip = re.sub(r'"', "", ip)
        if re.search(r"(\[.*\])", ip):
            _not_nest = False
            nest = re.split(r",(!?\[.*\])", ip)
            nest = filter(None, nest)
            # unnest from _ip_list
            _return_ips = []
            for item in nest:
                if re.match(r"^\[|^!\[", item):
                    nested = self.__flatten_ip(item)
                    _return_ips.append(nested)
                    continue
                _ip_list = self.__form_ip_list(item)
                for _ip in _ip_list:
                    _return_ips.append(_ip)
            return list_deny, _return_ips
        if _not_nest:
            _ip_list = self.__form_ip_list(ip)
            return list_deny, _ip_list
        return None

    def __validate_ip(self, ips):
        variables = {
            "$EXTERNAL_NET",
            "$HTTP_SERVERS",
            "$INTERNAL_NET",
            "$SQL_SERVERS",
            "$SMTP_SERVERS",
            "$DNS_SERVERS",
            "$HOME_NET",
            "HOME_NET",
            "any",
        }

        for item in ips:

            if isinstance(item, bool):
                pass

            if isinstance(item, list):
                for ip in item:
                    self.__validate_ip(ip)

            if isinstance(item, str):
                if item not in variables:
                    if "/" in item:
                        ipaddress.ip_network(item)
                    else:
                        ipaddress.ip_address(item)
        return True

    def ip(self, ip):
        if isinstance(ip, str):
            ip = ip.strip('"')
            if re.search(r",", ip):
                item = self.__flatten_ip(ip)
                ip = item
            else:
                ip = self.__ip_to_tuple(ip)
            valid = self.__validate_ip(ip)
            if valid:
                return ip
            raise ValueError(f"Invalid IP or variable: {ip}")
        return None

    # pylint: disable=too-many-branches
    # pylint: disable=too-many-locals
    # pylint: disable=too-many-statements
    @staticmethod
    def port(port):
        variables = {"any", "$HTTP_PORTS"}

        # is the source marked as not
        if port.startswith("!"):
            if_not = False
            port = port.strip("!")
        else:
            if_not = True
        # is it a list ?
        # if it is, then make it a list from the string
        # Snort allows for ports marked between
        # square brackets and are used to define lists
        # correct:
        # >> [80:443,!90,8080]
        # >> ![80:443]
        # >> [!80:443]
        if port.startswith("["):
            if port.endswith("]"):
                port = port[1:-1].split(",")
            else:
                raise ValueError("Port list is malformed")

        if isinstance(port, list):
            ports = []

            for item in port:
                not_range = True

                if ":" in item:
                    # Checking later on if port is [prt:] or [:prt]
                    open_range = False
                    items = item.split(":", 1)
                    message = ""
                    for prt in items:
                        message = f"Port range is malformed {item}"
                        prt = prt.lstrip("!")
                        if not prt:
                            open_range = True
                            continue

                        try:
                            prt = int(prt)
                        except Exception as e:
                            raise ValueError(message) from e

                        if prt < 0 or prt > 65535:
                            raise ValueError(message)

                    for index, value in enumerate(items):
                        value = value.lstrip("!")
                        items[index] = value

                    if not open_range:
                        try:
                            a = int(items[-1])
                            b = int(items[0])
                        except Exception as e:
                            raise ValueError(message) from e
                        if a - b < 0:
                            raise ValueError(message)
                    not_range = False

                port_not = True
                if re.search("^!", item):
                    port_not = False
                    item = item.strip("!")
                if not_range:
                    if item.lower() or item in variables:
                        ports.append((port_not, item))
                        continue
                    try:
                        prt = int(item)
                        if prt < 0 or prt > 65535:
                            raise ValueError(f"Port is out of range {item}")
                    except ValueError as e:
                        raise ValueError(f"Unknown port {item}") from e
                ports.append((port_not, item))

            return if_not, ports

        if isinstance(port, str):
            # Parsing ports like: :8080, 80:, 80:443
            # and passes all variables ex: $HTTP
            # ranges do not accept denial (!)
            if port or port.lower() in variables or re.search(r"^\$+", port):
                return if_not, port

            if re.search(":", port):
                message = f"Port is out of range {port}"
                ports = port.split(":")
                for portl in ports:
                    portl.lstrip("!")
                    if not portl:
                        continue
                    if portl or portl.lower() in variables:
                        continue
                    try:
                        portl = int(portl)

                    except ValueError as e:
                        raise ValueError(message) from e
                    if portl < 0 or portl > 65535:
                        raise ValueError(message)

                return if_not, port

            # Parsing a single port
            # single port accepts denial.
            try:
                if int(port) <= 65535 or int(port) < 0:
                    return if_not, port

                if int(port) > 65535 or int(port) < 0:
                    raise ValueError

                return None  # TODO: verify this is intended behavior

            except Exception as e:
                msg = f'Unknown port: "{port}" '
                raise ValueError(msg) from e
        else:
            message = f'Unknown port "{port}"'
            raise ValueError(message)

    @staticmethod
    def destination(dst):
        destinations = {"->": "to_dst", "<>": "bi_direct"}

        if dst in destinations:
            return dst
        msg = f"Invalid destination variable {dst}"
        raise ValueError(msg)

    def get_header(self):
        if re.match(r"(^[a-z|A-Z].+?)?(\(.+;\)|;\s\))", self.rule.lstrip()):
            header = self.rule.split("(", 1)
            return header[0]
        msg = f"Error in syntax, check if rulehas been closed properly {self.rule} "
        raise SyntaxError(msg)

    @staticmethod
    def remove_leading_spaces(string: str) -> str:
        return string.strip()

    def get_options(self):
        options = f"{self.rule.split('(', 1)[-1].lstrip().rstrip()}"
        if not options.endswith(")"):
            raise ValueError(
                "Snort rule options is not closed properly, " "you have a syntax error"
            )

        op_list = []

        value = ""
        option = ""
        last_char = ""

        for char in options.rstrip(")"):
            if char != ";":
                value = value + char
                option = option + char

            if char == ";" and last_char != "\\":
                op_list.append(option.strip())
                value = option = ""

            last_char = char

        return op_list

    def parse_header(self):  # pylint: disable=too-many-statements
        # OrderedDict(
        #     [
        #         ("action", "alert"),
        #         ("proto", "tcp"),
        #         ("source", (True, "$HOME_NET")),
        #         ("src_port", (True, "any")),
        #         ("arrow", "->"),
        #         ("destination", (False, "$EXTERNAL_NET")),
        #         ("dst_port", (True, "any")),
        #     ]
        # )

        if self.get_header():
            header = self.get_header()
            if re.search(r"[,\[\]]\s", header):
                header = re.sub(r",\s+", ",", header)
                header = re.sub(r"\s+,", ",", header)
                header = re.sub(r"\[\s+", "[", header)
                header = re.sub(r"\s+\]", "]", header)
            header = header.split()
        else:
            raise ValueError("Header is missing, or unparsable")
        # get rid of empty list elements
        header = list(filter(None, header))
        header_dict = collections.OrderedDict()
        size = len(header)
        if not size == 7 and not size == 1:
            msg = f"Snort rule header is malformed {header}"
            raise ValueError(msg)

        for item in header:
            if "action" not in header_dict:
                action = self.actions(item)
                header_dict["action"] = action
                continue

            if "proto" not in header_dict:
                try:
                    proto = self.proto(item)
                    header_dict["proto"] = proto
                    continue
                except Exception as perror:
                    raise ValueError(perror) from perror

            if "source" not in header_dict:
                try:
                    src_ip = self.ip(item)
                    header_dict["source"] = src_ip
                    continue
                except Exception as serror:
                    raise ValueError(serror) from serror

            if "src_port" not in header_dict:
                src_port = self.port(item)
                header_dict["src_port"] = src_port
                continue

            if "arrow" not in header_dict:
                dst = self.destination(item)
                header_dict["arrow"] = dst
                continue

            if "destination" not in header_dict:
                dst_ip = self.ip(item)
                header_dict["destination"] = dst_ip
                continue

            if "dst_port" not in header_dict:
                dst_port = self.port(item)
                header_dict["dst_port"] = dst_port
                continue

        return header_dict

    def parse_options(self, rule=None):
        if rule:
            self.rule = rule
        opts = self.get_options()

        options_dict = collections.OrderedDict()
        for index, option_string in enumerate(opts):
            if ":" in option_string:
                option = option_string.split(":", 1)
                key, value = option
                if key != "pcre":
                    value = value.split(",")
                options_dict[index] = (key, value)
            else:
                options_dict[index] = (option_string, "")
        return options_dict

    def validate_options(self, options):
        for _index, option in options.items():
            key, value = option
            if len(value) == 1:
                content_mod = self.dicts.content_modifiers(value[0])
                opt = False
                if content_mod:
                    # TODO: implement this feature
                    continue
            gen_option = self.dicts.options(key)
            if gen_option:
                opt = True
                continue
            pay_option = self.dicts.options(key)
            if pay_option:
                opt = True
                continue
            non_pay_option = self.dicts.options(key)
            if non_pay_option:
                opt = True
                continue
            post_detect = self.dicts.options(key)
            if post_detect:
                opt = True
                continue
            threshold = self.dicts.options(key)
            if threshold:
                opt = True
                continue
            if not opt:
                message = f"unrecognized option: {key}"
                raise ValueError(message)
        return options


class Sanitizer:
    def __init__(self):
        self.methods = {
            "pcre": self.pcre,
        }

    def sanitize(self, parsed):
        options = parsed["options"]
        for key, value in options.items():
            if key in self.methods:
                options[key] = self.methods[key](value)

        parsed["options"] = options
        return parsed

    @staticmethod
    def pcre(value: list) -> List:
        value_string = value[0]
        if re.match(r'^"/.*/[ismxAEGRUBPHMCOIDKYS]+"$', value_string):
            return value
        if not str(value).startswith('"/') and value:
            start = re.split(r'^"', value)
            start[0] = '"/'
            value = "".join(start)
        if not re.search(r'(\/")$', value):
            end = re.split(r'"$', value)
            end[-1] = '/"'
            value = "".join(end)
        return value

    @staticmethod
    def depth(options):
        depth_idx = [idx for idx in options if "depth" in options[idx]][0]
        dsize_idx = [idx for idx in options if "dsize" in options[idx]][0]
        depth = options[depth_idx].get("depth")[0]
        dsize = options[dsize_idx].get("dsize")[0]
        full_dsize = re.split(r"[0-9]+", dsize)
        operand = [x for x in full_dsize if x]
        dsize = dsize.strip(operand[0])
        if int(depth) < int(dsize):
            return dsize
        return depth


class SerializeRule:
    def __init__(self, rule):
        self.rule = rule

    def __getitem__(self, key):
        if "rule" in key:
            return self.serialize_rule()
        if "header" in key:
            return self.serialize_header()
        if "options" in key:
            return self.serialize_options()
        return None

    def __str__(self):
        return self.serialize_rule()

    def __list_serializer(self, list_bool: bool, items: List) -> str:
        serialised = str()
        for _bool, item in items:
            if isinstance(item, list):
                serialised = f"{serialised},{self.__list_serializer(_bool, item)}"
            else:
                if _bool:
                    serialised = f"{serialised},{item}"
                if not _bool:
                    serialised = f"{serialised},!{item}"

        serialised_list = serialised.lstrip(",")

        if list_bool:
            serialised = f"[{serialised_list}]"
        else:
            serialised = f"![{serialised_list}]"

        return serialised

    def serialize_header_item(self, item: Any) -> Optional[str]:
        if isinstance(item, str):
            return item

        if isinstance(item, tuple):
            _bool, item = item
            if isinstance(item, list):
                return self.__list_serializer(_bool, item)
            return item
        return None  # TODO: verify this is intended behavior

    def serialize_header(self, header: Dict = None) -> str:
        serialised = str()
        if not header:
            header = self.rule["header"]
        assert header is not None
        for _key, value in header.items():
            item = self.serialize_header_item(value)
            serialised = f"{serialised} {item}"
        return serialised

    def serialize_options(self, options: Dict = None) -> str:
        options_list = []
        if not options:
            options = self.rule["options"]
        assert options is not None
        for _index, option in options.items():
            key, value = option
            if value:
                option_value = f"{key}:{','.join(value)}"
            else:
                option_value = f"{key}"
            options_list.append(option_value)

        _options = "; ".join(str(e) for e in options_list)
        serialized_options = f"({_options})"
        return serialized_options

    def serialize_rule(self):
        return f"{self.serialize_header()} {self.serialize_options()}".lstrip()
