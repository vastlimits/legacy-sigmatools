import json
import re
import sigma
import os
from sigma.backends.base import SingleTextQueryBackend
from sigma.parser.condition import SigmaAggregationParser, NodeSubexpression, ConditionAND, ConditionOR, ConditionNOT
from sigma.parser.exceptions import SigmaParseError
from .mixins import MultiRuleOutputMixin
from sigma.parser.modifiers.transform import SigmaContainsModifier, SigmaStartswithModifier, SigmaEndswithModifier
from sigma.parser.modifiers.type import SigmaRegularExpressionModifier
from ..parser.modifiers.base import SigmaTypeModifier

gUnsupportedCategories = {}
gPlatformLevelCombinations = {}

UA_VERSION_6_0 = "6.0.0"
UA_VERSION_6_1 = "6.1.0"
UA_VERSION_6_2 = "6.2.0"
UA_VERSION_7_0 = "7.0.0"
UA_VERSION_7_1 = "7.1.0"

# Next upcoming version (version number not yet assigned)
UA_VERSION_DEVELOP = "develop"
UA_VERSION_CURRENT_RELEASE = UA_VERSION_7_0


class Versioning:
    def __init__(self, version):

        # It is possible to initialize version with Major.Minor, e.g: 6.0, 7.0
        # However, internally we need build number. Simply append it.
        if version.count('.') == 1:
            version += ".0"
        elif version == "main":
            version = UA_VERSION_CURRENT_RELEASE
            
        self._outputVersion = version

    def is_version_6_1_or_newer(self):
        return self.is_version_develop() or self._version() >= self._version_tuple(UA_VERSION_6_1)

    def is_version_6_2_or_newer(self):
        return self.is_version_develop() or self._version() >= self._version_tuple(UA_VERSION_6_2)

    def is_version_7_0_or_newer(self):
        return self.is_version_develop() or self._version() >= self._version_tuple(UA_VERSION_7_0)
        
    def is_version_7_1_or_newer(self):
        return self.is_version_develop() or self._version() >= self._version_tuple(UA_VERSION_7_1)

    def is_version_develop(self):
        return self._outputVersion == UA_VERSION_DEVELOP

    def is_sigma_platform_supported(self, platform):
        platform_per_version = {
            UA_VERSION_6_0: ["common", "windows"],
            UA_VERSION_DEVELOP: ["common", "windows", "macos"]
        }

        if platform in platform_per_version[UA_VERSION_6_0]:
            return True

        if (self.is_version_develop() or self.is_version_7_1_or_newer) and platform in platform_per_version[UA_VERSION_DEVELOP]:
            return True

    def is_field_supported(self, field):
        fields_per_version = {
            UA_VERSION_6_0: [
                "Process.Name",
                "Parent.Name",
                "Process.User",
                "Parent.User",
                "Process.Path",
                "Parent.Path",
                "Process.CommandLine",
                "Parent.CommandLine",
                "Process.AppName",
                "Parent.AppName",
                "Process.AppVersion",
                "Parent.AppVersion",
                "Process.Company",
                "Parent.Company",
                "Process.IsElevated",
                "Parent.IsElevated",
                "Process.IsProtected",
                "Parent.IsProtected",
                "Process.SessionId",
                "Parent.SessionId",
                "Process.DirectorySdSddl",
                "Process.DirectoryUserWritable",
                "Process.Hash",
                "Parent.Hash",
                "Net.Target.Ip",
                "Net.Target.Name",
                "Net.Target.Port",
                "Net.Target.Protocol",
                "Reg.Key.Path",
                "Reg.Key.Name",
                "Reg.Parent.Key.Path",
                "Reg.Key.Path.New",
                "Reg.Key.Path.Old",
                "Reg.Value.Name",
                "Reg.File.Name",
                "Reg.Key.Sddl",
                "Reg.Key.Hive",
                "Image.Name",
                "Image.Path",
                "Image.Hash"
            ],
            UA_VERSION_6_1: [
                "Process.Hash.MD5",
                "Process.Hash.SHA1",
                "Process.Hash.SHA256",
                "Process.Hash.IMP",
                "Process.IsSigned",
                "Process.Signature",
                "Process.SignatureStatus",
                "Parent.Hash.MD5",
                "Parent.Hash.SHA1",
                "Parent.Hash.SHA256",
                "Parent.Hash.IMP",
                "Parent.IsSigned",
                "Parent.Signature",
                "Parent.SignatureStatus",
                "Image.Hash.MD5",
                "Image.Hash.SHA1",
                "Image.Hash.SHA256",
                "Image.Hash.IMP",
                "Image.IsSigned",
                "Image.Signature",
                "Image.SignatureStatus"
            ],
            UA_VERSION_6_2: [
                "Net.Target.IpIsV6",
                "Net.Target.PortName",
                "Net.Source.Ip",
                "Net.Source.IpIsV6",
                "Net.Source.Name",
                "Net.Source.Port",
                "Net.Source.PortName",
                "Thread.Id",
                "Thread.Timestamp",
                "Thread.Process.Id",
                "Thread.Parent.Id",
                "Thread.StartAddress",
                "Thread.StartModule",
                "Thread.StartFunctionName",
                "Reg.Key.Target",
                "Process.Hashes",
                "Parent.Hashes",
                "Image.Hashes"
            ],
            UA_VERSION_7_0: [
                "Image.IsSignedByOSVendor",
                "Process.IsSignedByOSVendor",
                "Parent.IsSignedByOSVendor"
            ]
        }

        if self.is_version_6_1_or_newer():
            # The fields here were removed in version 6.1.0 and replaced with more specific fields.
            # Remove them if we are generating for a newer version, so we don't generate invalid rules.
            fields_per_version[UA_VERSION_6_0].remove("Process.Hash")
            fields_per_version[UA_VERSION_6_0].remove("Parent.Hash")
            fields_per_version[UA_VERSION_6_0].remove("Image.Hash")

        if field in fields_per_version[UA_VERSION_6_0]:
            return True

        if self.is_version_6_1_or_newer() and field in fields_per_version[UA_VERSION_6_1]:
            return True

        if self.is_version_6_2_or_newer() and field in fields_per_version[UA_VERSION_6_2]:
            return True

        return False

    def is_sigma_category_supported(self, category):
        """Returns whether uberAgent ESA knows the given sigma category or not."""
        event_type = self.convert_category(category)
        event_types_per_version = {
            UA_VERSION_6_0: [
                "Process.Start",
                "Process.Stop",
                "Image.Load",
                "Net.Send",
                "Net.Receive",
                "Net.Connect",
                "Net.Reconnect",
                "Net.Retransmit",
                "Reg.Key.Create",
                "Reg.Value.Write",
                "Reg.Delete",
                "Reg.Key.Delete",
                "Reg.Value.Delete",
                "Reg.Key.SecurityChange",
                "Reg.Key.Rename",
                "Reg.Key.SetInformation",
                "Reg.Key.Load",
                "Reg.Key.Unload",
                "Reg.Key.Save",
                "Reg.Key.Restore",
                "Reg.Key.Replace",
                "Reg.Any"
            ],
            UA_VERSION_6_1: [
                "DNS.Event"
            ],
            UA_VERSION_6_2: [
                "Net.Any",
                "Process.CreateRemoteThread",
                "Process.TamperingEvent"
            ],
            UA_VERSION_DEVELOP: []
        }

        if event_type in event_types_per_version[UA_VERSION_6_0]:
            return True

        if self.is_version_6_1_or_newer() and event_type in event_types_per_version[UA_VERSION_6_1]:
            return True

        if self.is_version_6_2_or_newer() and event_type in event_types_per_version[UA_VERSION_6_2]:
            return True

        if self.is_version_develop() and event_type in event_types_per_version[UA_VERSION_DEVELOP]:
            return True

    def _version(self):
        return self._version_tuple(self._outputVersion)

    @staticmethod
    def convert_category(category):

        # Maps a sigma category to uberAgent's Activity Monitoring Event Type
        category_map = {
            "process_creation": "Process.Start",
            "image_load": "Image.Load",
            "dns": "Dns.Query",
            "dns_query": "Dns.Query",
            "network_connection": "Net.Any",
            "firewall": "Net.Any",
            "create_remote_thread": "Process.CreateRemoteThread",
            "registry_event": "Reg.Any",
            "registry_add": "Reg.Any",
            "registry_delete": "Reg.Any",
            "registry_set": "Reg.Any",
            "registry_rename": "Reg.Any"
        }

        if category in category_map:
            return category_map[category]

        if category in gUnsupportedCategories:
            gUnsupportedCategories[category] += 1
        else:
            gUnsupportedCategories[category] = 1

        return None

    # Builds a version tuple which works fine as long as we specify the version in Major.Minor.Build.
    # A more efficient and robust way to solve this is using packaging.version but since we dont want to add
    # more dependencies to sigmac were using this method.
    # Because we specify versions in the same format, this is going to be fine.
    @staticmethod
    def _version_tuple(v):
        return tuple(map(int, (v.split("."))))

    def get_filename(self, rule):

        # File name since develop (upcoming version)
        if self.is_version_develop() or self.is_version_7_1_or_newer():
            return "uberAgent-ESA-am-sigma-" + rule.sigma_level + "-" + rule.platform + ".conf"

        # File name since 6.2
        if self.is_version_6_2_or_newer():
            return "uberAgent-ESA-am-sigma-" + rule.sigma_level + ".conf"

        # File name since initial version 6.0
        return "uberAgent-ESA-am-sigma-proc-creation-" + rule.sigma_level + ".conf"


gVersion: Versioning = None


def convert_sigma_level_to_uberagent_risk_score(level):
    """Converts the given Sigma rule level to uberAgent ESA RiskScore property."""
    levels = {
        "critical": 100,
        "high": 75,
        "medium": 50,
        "low": 25,
        "informational": 1
    }

    if level in levels:
        return levels[level]

    return 0


def convert_sigma_name_to_uberagent_tag(name):
    """Converts the given Sigma rule name to uberAgent ESA Tag property."""
    tag = name.lower().replace(" ", "-")
    tag = re.sub(r"-{2,}", "-", tag, 0, re.IGNORECASE)
    return tag


class IgnoreTypedModifierException(Exception):
    """
    IgnoreTypedModifierException
    Helper class to ignore exceptions of type identifiers that are not yet supported.
    """
    pass


class IgnoreFieldException(Exception):
    """
    IgnoreFieldException
    Helper class to ignore exceptions of specific fields that are not yet supported.
    """
    pass


class IgnoreAggregationException(Exception):
    """
    IgnoreAggregationException
    Helper class to ignore exceptions of aggregation rules that are not yet supported.
    """


class MalformedRuleException(Exception):
    """
    MalformedRuleException
    Helper class to ignore exceptions of malformed rules.
    """
    pass


class ActivityMonitoringRule:
    """
    ActivityMonitoringRule
    This class wraps a [ActivityMonitoringRule] configuration block.
    """

    def __init__(self):
        self.id = ""
        self.name = ""
        self.event_type = None
        self.tag = ""
        self.query = ""
        self.risk_score = 0
        self.description = ""
        self.sigma_level = ""
        self.annotation = ""
        self.generic_properties = []
        self.platform = ""
        self.author = ""

    # Query =
    # Available since uberAgent 6.0+
    def set_query(self, query):
        """Sets the generated query property."""
        self.query = query

    # RuleName =
    # Available since uberAgent 6.0+
    def set_name(self, name):
        """Sets the RuleName."""
        self.name = name

    # Tag =
    # Available since uberAgent 6.0+
    def set_tag(self, tag):
        """Sets the Tag property."""
        self.tag = tag

    # EventType =
    # Available since uberAgent 6.0+
    def set_event_type(self, event_type):
        """Sets the EventType property."""
        self.event_type = event_type

    # RiskScore =
    # Available since uberAgent 6.0+
    def set_risk_score(self, risk_score):
        """Sets the RiskScore property."""
        self.risk_score = risk_score

    # RuleId =
    # Available since uberAgent 7.0+
    def set_id(self, rule_id):
        """Sets the RuleId property."""
        self.id = rule_id

    # Annotation =
    # Available since uberAgent 7.0+
    def set_annotation(self, annotation):
        """Set the Annotation property."""
        self.annotation = annotation

    # GenericProperty1 =
    # ..
    # GenericPropertyN =
    # Available since uberAgent 6.1+
    def set_generic_properties(self, fields):
        """Set the generic properties. """
        self.generic_properties = fields

    # Not used as configuration setting, but to determine in which file the rule is being saved.
    # Available since uberAgent 6.0+
    def set_sigma_level(self, level):
        """Sets the Sigma rule level."""
        self.sigma_level = level

    # Not used as configuration setting, but to comment the rule.
    # Available since uberAgent 6.0+
    def set_description(self, description):
        """Set the Description property."""
        self.description = description

    # Not used as configuration setting, but to comment the rule.
    # Backported to all uberAgent versions.
    def set_author(self, author):
        """Set the Author property."""
        self.author = author

    # Used to determine the platform where a rule is being evaluated on.
    # Adds the platform = X configuration to a [ActivityMonitoringRule] stanza.
    #
    # Available since uberAgent 7.0+
    def set_platform(self, product):
        """Set the platform property. """
        self.platform = product

    # Utility to make/modify tag names.
    def _prefixed_tag(self):
        prefixes = {
            "Process.Start": "proc-start"
        }

        if self.event_type not in prefixes:
            return self.tag

        return "{}-{}".format(prefixes[self.event_type], self.tag)

    def __str__(self):
        """Builds and returns the [ActivityMonitoringRule] configuration block."""

        global gVersion

        # The default is available since uberAgent 6.
        result = "[ActivityMonitoringRule]\n"

        # Starting with uberAgent 7.1 and newer we slightly change the configuration stanza.
        # Example. [ActivityMonitoringRule platform=Windows] or [ActivityMonitoringRule platform=MacOS]
        if gVersion.is_version_7_1_or_newer():
            result = "[ActivityMonitoringRule"
            if self.platform in ["windows", "macos"]:
                result += " platform="
                if self.platform == "windows":
                    result += "Windows"
                elif self.platform == "macos":
                    result += "MacOS"
            result += "]\n"

        # The Description is optional.
        if len(self.description) > 0:
            for description_line in self.description.splitlines():
                result += "# {}\n".format(description_line)

        if len(self.author) > 0:
            result += "# Author: {}\n".format(self.author)

        # Make sure all required properties have at least a value that is somehow usable.
        if self.event_type is None:
            raise MalformedRuleException()

        if len(self.tag) == 0:
            raise MalformedRuleException()

        if len(self.name) == 0:
            raise MalformedRuleException()

        if len(self.query) == 0:
            raise MalformedRuleException()

        if gVersion.is_version_7_0_or_newer():
            result += "RuleId = {}\n".format(self.id)

        result += "RuleName = {}\n".format(self.name)
        result += "EventType = {}\n".format(self.event_type)
        result += "Tag = {}\n".format(self._prefixed_tag())

        # The RiskScore is optional.
        # Set it, if a risk_score value is present.
        if self.risk_score > 0:
            result += "RiskScore = {}\n".format(self.risk_score)

        if gVersion.is_version_7_0_or_newer():
            if len(self.annotation) > 0:
                result += "Annotation = {}\n".format(self.annotation)

        result += "Query = {}\n".format(self.query)

        if self.event_type == "Reg.Any":
            result += "Hive = HKLM,HKU\n"

        # uberAgent supports generic properties to be added to an activity rule since version 6.1
        if gVersion.is_version_6_1_or_newer():
            counter = 1
            for prop in self.generic_properties:

                # The following properties are included in all tagging events anyways.
                # There is no need to send them twice to the backend so we are ignoring them here.
                if prop in ["Process.Path", "Process.CommandLine", "Process.Name"]:
                    continue
                # Generic properties are limited to 10.
                if counter > 10:
                    break

                result += "GenericProperty{} = {}\n".format(counter, prop)
                counter += 1

        return result


def get_mitre_annotation_from_tag(tag):
    tag = tag.lower()
    if tag.startswith('attack.t'):
        return tag[7:].upper()
    return None


def get_annotation(tags):
    mitre_annotation_objects = []
    for tag in tags:
        mitre_annotation = get_mitre_annotation_from_tag(tag)
        if mitre_annotation is not None:
            mitre_annotation_objects.append(mitre_annotation)

    if len(mitre_annotation_objects) > 0:
        return json.dumps({'mitre_attack': mitre_annotation_objects})

    return ""


def get_parser_properties(sigmaparser):
    title = sigmaparser.parsedyaml['title']
    level = sigmaparser.parsedyaml['level']
    description = sigmaparser.parsedyaml['description']
    condition = sigmaparser.parsedyaml['detection']['condition']
    logsource = sigmaparser.parsedyaml['logsource']
    rule_id = sigmaparser.parsedyaml['id']
    author = ''

    if 'author' in sigmaparser.parsedyaml:
        author = sigmaparser.parsedyaml['author']

    category = ''
    if 'category' in logsource:
        category = logsource['category'].lower()

    product = ''
    if 'product' in logsource:
        product = logsource['product'].lower()

    service = ''
    if 'service' in logsource:
        service = logsource['service'].lower()

    annotation = ''
    if 'tags' in sigmaparser.parsedyaml:
        annotation = get_annotation(sigmaparser.parsedyaml['tags'])

    return product, category, service, title, level, condition, description, annotation, rule_id, author


def write_file_header(f, level):
    f.write("#\n")
    f.write("# The rules are generated from the Sigma GitHub repository at https://github.com/SigmaHQ/sigma\n")
    f.write("# Follow these steps to get the latest rules from the repository with Python\n")
    f.write("#    1. Clone the repository locally\n")
    f.write("#    2. Using a commandline, change working directory to the just cloned repository\n")
    f.write("#    3. Run sigmac -I --target uberagent -r rules/\n")
    f.write("#\n")
    f.write("# The rules in this file are marked with sigma-level: {}\n".format(level))
    f.write("#\n\n")

def create_configuration_file(file_name, sigma_level):
    # First remove old files if present
    if os.path.exists(file_name):
        try:
            os.remove(file_name)
        except OSError as error:
            print("There was an error deleting previously created files:" + error)
            print("Please remove them manually or try again.")
            exit(1)
    
    if not os.path.exists(file_name):
        with open(file_name, "w", encoding='utf8') as file:
            write_file_header(file, sigma_level)
            file.close()

class uberAgentBackend(SingleTextQueryBackend):
    """Converts Sigma rule into uberAgent ESA's process tagging rules."""
    identifier = "uberagent"
    active = True
    config_required = False
    rule = None
    current_category = None
    recent_fields = []

    #
    # SingleTextQueryBackend
    #
    andToken = " and "
    orToken = " or "
    notToken = "not "
    subExpression = "(%s)"
    listExpression = "[%s]"
    listSeparator = ", "
    valueExpression = "\"%s\""
    valueBooleanExpression = "%s"
    nullExpression = "%s == ''"
    notNullExpression = "%s != ''"
    mapExpression = "%s == %s"
    mapListsSpecialHandling = True
    mapListValueExpression = "%s in %s"

    # Syntax for swapping wildcard conditions: Adding \ as escape character
    # Wildcard conditions are based on modifiers such as contains,
    # startswith, endswith
    mapWildcard = "%s like r%s"

    #
    # uberAgent field mapping
    #
    fieldMapping = {
        "commandline": "Process.CommandLine",
        "image": "Process.Path",
        "originalfilename": "Process.Name",
        "imageloaded": "Image.Path",
        "imagepath": "Image.Path",
        "parentcommandline": "Parent.CommandLine",
        "parentprocessname": "Parent.Name",
        "parentimage": "Parent.Path",
        "path": "Process.Path",
        "processcommandline": "Process.CommandLine",
        "command": "Process.CommandLine",
        "processname": "Process.Name",
        "user": "Process.User",
        "username": "Process.User",
        "company": "Process.Company"
    }

    fieldMappingPerCategory = {
        "process_creation": {
            "sha1": "Process.Hash.SHA1",
            "imphash": "Process.Hash.IMP",
            "childimage": "Process.Path",
            "signed": "Process.IsSigned",
            "hashes": "Process.Hashes"
        },
        "image_load": {
            "sha1": "Image.Hash.SHA1",
            "imphash": "Image.Hash.IMP",
            "childimage": "Image.Path",
            "signed": "Image.IsSigned",
            "hashes": "Image.Hashes"
        },
        "dns": {
            "query": "Dns.QueryRequest",
            "answer": "Dns.QueryResponse"
        },
        "dns_query": {
            "queryname": "Dns.QueryRequest",
        },
        "network_connection": {
            "destinationport": "Net.Target.Port",
            "destinationip": "Net.Target.Ip",
            "destinationhostname": "Net.Target.Name",
            "destinationisipv6": "Net.Target.IpIsV6",
            "sourceport": "Net.Source.Port"
        },
        "firewall": {
            "destination.port": "Net.Target.Port",
            "dst_ip": "Net.Target.Ip",
            "src_ip": "Net.Source.Ip",
            "dst_port": "Net.Target.Port",
            "src_port": "Net.Source.Port"
        },
        "create_remote_thread": {
            "targetimage": "Process.Path",
            "startmodule": "Thread.StartModule",
            "startfunction": "Thread.StartFunctionName"
        },
        "registry_event": {
            "targetobject": "Reg.Key.Target",
            "newname": "Reg.Key.Path.New"
        },
        "registry_add": {
            "targetobject": "Reg.Key.Target",
            "newname": "Reg.Key.Path.New"
        },
        "registry_delete": {
            "targetobject": "Reg.Key.Target",
            "newname": "Reg.Key.Path.New"
        },
        "registry_set": {
            "targetobject": "Reg.Key.Target",
            "newname": "Reg.Key.Path.New"
        },
        "registry_rename": {
            "targetobject": "Reg.Key.Target",
            "newname": "Reg.Key.Path.New"
        }
    }

    # We ignore some fields that we don't support yet but we don't want them to
    # throw errors in the console since we are aware of this.
    ignoreFieldList = [
        "description",
        "product",
        "logonid",
        "integritylevel",
        "currentdirectory",
        "parentintegritylevel",
        "eventid",
        "parentuser",
        "parent_domain",
        "signed",
        "parentofparentimage",
        "record_type",  # Related to network (DNS).
        "querystatus",  # Related to network (DNS).
        "initiated",  # Related to network connections. Seen as string 'true' / 'false'.
        "action",  # Related to firewall category.
        "targetprocessaddress",
        "sourceimage",
        "eventtype",
        "details"
    ]

    booleanFieldList = [
        "Process.IsElevated",
        "Parent.IsElevated",
        "Process.IsProtected",
        "Parent.IsProtected",
        "Process.DirectoryUserWriteable",
        "Process.IsSigned",
        "Process.IsSignedByOSVendor",
        "Parent.IsSigned",
        "Parent.IsSignedByOSVendor",
        "Image.IsSigned",
        "Image.IsSignedByOSVendor",
        "Net.Target.IpIsV6",
        "Net.Source.IpIsV6",
        "File.IsExecutable"
    ]

    options = SingleTextQueryBackend.options + (
        ("exclusion", "", "List of separated GUIDs to execlude rule generation for.", None),
        ("version", "", "Specify uberAgent version to generate rules for.", None)
    )

    rules = []

    def trackRecentMappedField(self, field):
        if field not in self.recent_fields:
            self.recent_fields.append(field)

    def fieldNameMapping(self, field_name, value):
        key = field_name.lower()

        if self.current_category is not None:
            if self.current_category in self.fieldMappingPerCategory:
                if key in self.fieldMappingPerCategory[self.current_category]:
                    result = self.fieldMappingPerCategory[self.current_category][key]
                    self.trackRecentMappedField(result)
                    return result

        if key not in self.fieldMapping:
            if key in self.ignoreFieldList:
                raise IgnoreFieldException()
            else:
                raise NotImplementedError(
                    'The field name %s in category %s is not implemented.' % (field_name, self.current_category))

        result = self.fieldMapping[key]

        # We have a valid field.
        # But we must check if this field is supported in the given uberAgent version.
        global gVersion
        if not gVersion.is_field_supported(result):
            raise NotImplementedError('The field name %s in category %s is not implemented in the specified uberAgent '
                                      'version. Please upgrade to a newer uberAgent version.' % (field_name,
                                                                                                 self.current_category))

        self.trackRecentMappedField(result)
        return result

    def generateQuery(self, parsed):
        if parsed.parsedAgg:
            raise IgnoreAggregationException()

        return self.generateNode(parsed.parsedSearch)

    def generate(self, sigmaparser):

        # Initialize version class to easily handle multiple output version.
        # The version is specified in backend configuration.
        # Example
        #
        # version: UA_VERSION_DEVELOP (upcoming version for development purposes)
        # version: UA_VERSION_6_0
        # version: UA_VERSION_6_1
        # version: UA_VERSION_7_0
        #
        global gVersion
        if gVersion is None:
            gVersion = Versioning(self.backend_options["version"])

        """Method is called for each sigma rule and receives the parsed rule (SigmaParser)"""
        platform, category, service, title, level, condition, description, annotation, rule_id, author = get_parser_properties(
            sigmaparser)

        # Exclude all entries contained in backend configuration exclusion list.
        if rule_id in self.backend_options["exclusion"]:
            return ""

        # Empty platform indicates a common rule that does not depend on a specific platform
        if platform == "":
            platform = "common"

        # Do not generate a rule if the given category is unsupported
        if not gVersion.is_sigma_category_supported(category):
            return ""

        # Do not generate a rule if the given platform is unsupported
        if not gVersion.is_sigma_platform_supported(platform):
            return ""

        self.current_category = category

        try:
            rule = ActivityMonitoringRule()
            self.recent_fields = []

            query = super().generate(sigmaparser)
            if len(query) > 0:
                rule.set_id(rule_id)
                rule.set_name(title)
                rule.set_tag(convert_sigma_name_to_uberagent_tag(title))
                rule.set_event_type(Versioning.convert_category(category))
                rule.set_query(query)
                rule.set_risk_score(convert_sigma_level_to_uberagent_risk_score(level))
                rule.set_sigma_level(level)
                rule.set_description(description)
                rule.set_author(author)
                rule.set_annotation(annotation)
                rule.set_generic_properties(self.recent_fields)
                rule.set_platform(platform)
                self.rules.append(rule)
                gPlatformLevelCombinations[level + "-" + platform] = 0
                print("Generated rule <{}>.. [level: {}]".format(rule.name, level))
        except IgnoreTypedModifierException:
            return ""
        except IgnoreAggregationException:
            return ""
        except IgnoreFieldException:
            return ""
        except MalformedRuleException:
            return ""
            
    def prepare_configuration_files(self):
        sigma_levels = {"critical", "high", "medium", "low", "informational"}
        platforms = {"common", "macos", "windows"}    
        
        file_prefix = "uberAgent-ESA-am-sigma-proc-creation-"
        if gVersion.is_version_6_2_or_newer():
            file_prefix = "uberAgent-ESA-am-sigma-"
        
        for sigma_level in sigma_levels:
            if gVersion.is_version_7_1_or_newer():
                for platform in platforms:        
                    file_name = file_prefix + sigma_level + "-" + platform + ".conf"
                    create_configuration_file(file_name, sigma_level)        
            else:
                file_name = file_prefix + sigma_level + ".conf"
                create_configuration_file(file_name, sigma_level)
            
            
    def serialize_rules(self):
        result_dict = {
            "common critical": 0,
            "common high": 0,
            "common medium": 0,
            "common low": 0,
            "common informational": 0,
            "windows critical": 0,
            "windows high": 0,
            "windows medium": 0,
            "windows low": 0,
            "windows informational": 0,
            "macos critical": 0,
            "macos high": 0,
            "macos medium": 0,
            "macos low": 0,
            "macos informational": 0
        }

        self.prepare_configuration_files()

        for rule in self.rules:
            file_name = gVersion.get_filename(rule)
            with open(file_name, "a", encoding='utf8') as file:
                try:
                    serialized_rule = str(rule)
                    file.write(serialized_rule + "\n")
                except MalformedRuleException:
                    continue
                file.close()
                key = rule.platform + " " + rule.sigma_level
                result_dict[key] += 1

        print("Generated {} activity monitoring rules..".format(len(self.rules)))
        print("This includes..")

        report_string = "{} for Windows, {} for macOS, {} platform independent."

        print(("Critical severity: " + report_string).format(result_dict["windows critical"],
                                                             result_dict["macos critical"],
                                                             result_dict["common critical"]))

        print(("High severity:     " + report_string).format(result_dict["windows high"],
                                                             result_dict["macos high"],
                                                             result_dict["common high"]))

        print(("Medium severity:   " + report_string).format(result_dict["windows medium"],
                                                             result_dict["macos medium"],
                                                             result_dict["common medium"]))

        print(("Low severity:      " + report_string).format(result_dict["windows low"],
                                                             result_dict["macos low"],
                                                             result_dict["common low"]))

        print(("Informational:     " + report_string).format(result_dict["windows informational"],
                                                             result_dict["macos informational"],
                                                             result_dict["common informational"]))

    def finalize(self):
        self.serialize_rules()
        print("There are %d unsupported categories." % len(gUnsupportedCategories))
        for category in gUnsupportedCategories:
            print("Category %s has %d unsupported rules." % (category, gUnsupportedCategories[category]))

    def generateNode(self, node):
        if type(node) == bool:
            return self.valueBooleanExpression % str(node).lower()
        return super(uberAgentBackend, self).generateNode(node)

    def generateTypedValueNode(self, node):
        raise IgnoreTypedModifierException()

    def generateMapItemTypedNode(self, fieldname, value):
        raise IgnoreTypedModifierException()

    def generateMapItemListNode(self, key, value):
        if type(value) == NodeSubexpression:
            value = value.items
        return "(" + (" or ".join([self.mapWildcard % (key, self.generateValueNode(item)) for item in value])) + ")"

    def generateMapItemNode(self, node):
        field_name, value = node
        transformed_field_name = self.fieldNameMapping(field_name, value)

        if value is None:
            return self.nullExpression % (transformed_field_name,)

        has_wildcard = re.search(r"((\\(\*|\?|\\))|\*|\?|_|%)", self.generateNode(value))

        if transformed_field_name in self.booleanFieldList and type(value) == str:
            if value.lower() in ['true', '1']:
                value = True
            else:
                value = False

        if "," in self.generateNode(value) and not has_wildcard:
            return self.mapListValueExpression % (transformed_field_name, self.generateNode(value))
        elif type(value) in (list, NodeSubexpression):
            return self.generateMapItemListNode(transformed_field_name, value)
        elif self.mapListsSpecialHandling is False and type(value) in (
                str, int, bool, list) or self.mapListsSpecialHandling is True and type(value) in (str, int, bool):
            if has_wildcard:
                return self.mapWildcard % (transformed_field_name, self.generateNode(value))
            else:
                return self.mapExpression % (transformed_field_name, self.generateNode(value))
        elif has_wildcard:
            return self.mapWildcard % (transformed_field_name, self.generateNode(value))
        else:
            raise TypeError("Backend does not support map values of type " + str(type(value)))

    def cleanValue(self, val):
        if not isinstance(val, str):
            return str(val)

        # Single backlashes which are not in front of * or ? are doubled
        val = re.sub(r"(?<!\\)\\(?!(\\|\*|\?))", r"\\\\", val)

        # Replace _ with \_ because _ is a sql wildcard
        val = re.sub(r'_', r'\_', val)

        # Replace % with \% because % is a sql wildcard
        val = re.sub(r'%', r'\%', val)

        # Replace " with \" because " is a string literal symbol and must be escaped
        val = re.sub(r'"', r'\"', val)

        # Replace * with %, if even number of backslashes (or zero) in front of *
        val = re.sub(r"(?<!\\)(\\\\)*(?!\\)\*", r"\1%", val)

        # Replace ? with _, if even number of backslashes (or zero) in front of ?
        val = re.sub(r"(?<!\\)(\\\\)*(?!\\)\?", r"\1_", val)
        return val
