[![sigma build status](https://github.com/SigmaHQ/legacy-sigmatools/actions/workflows/sigma-test.yml/badge.svg?branch=master)](https://github.com/SigmaHQ/legacy-sigmatools/actions?query=branch%3Amaster)

![sigma_logo](./images/Sigma_0.3.png)

# Sigma Legacy Tools

This repository contains the Sigma legacy toolchain mostly known for the first iteration of the Sigma conversion tool,
*sigmac*. Please don't use this anymore in new projects or provide new backends to this project, because it is not
actively maintained anymore and was replaced with [pySigma](https://github.com/SigmaHQ/pySigma) (library) and [Sigma
CLI](https://github.com/SigmaHQ/sigma-cli) (command line tool including conversion based on pySigma).

Sigma itself is the generic signature format for SIEM systems, check the [main rule
repository](https://github.com/SigmaHQ/sigma) for further information.

## Sigmac

Sigmac converts sigma rules into queries or inputs of the supported targets listed below. It acts as a frontend to the
Sigma library that may be used to integrate Sigma support in other projects. Further, there's `merge_sigma.py` which
merges multiple YAML documents of a Sigma rule collection into simple Sigma rules.

**WARNING: Do not provide conversion backends for this tool anymore. We'll soon set a date for its deprecation. Since October 2020, we're working on a much more flexible and stable module named [pySigma](https://github.com/SigmaHQ/pySigma) and a command line interface named [sigma-cli](https://github.com/SigmaHQ/sigma-cli) that makes use of pySigma.**

### Usage

```bash
usage: sigmac [-h] [--recurse] [--filter FILTER]
              [--target {sqlite,netwitness-epl,logpoint,graylog,netwitness,arcsight,carbonblack,es-rule,ala,elastalert-dsl,splunkxml,fieldlist,sysmon,arcsight-esm,kibana,csharp,qualys,powershell,es-qs,mdatp,humio,grep,qradar,logiq,sql,sumologic,ala-rule,limacharlie,elastalert,splunk,stix,xpack-watcher,crowdstrike,es-dsl,ee-outliers}]
              [--target-list] [--config CONFIG] [--output OUTPUT]
              [--backend-option BACKEND_OPTION] [--defer-abort]
              [--ignore-backend-errors] [--verbose] [--debug]
              [inputs [inputs ...]]

Convert Sigma rules into SIEM signatures.

positional arguments:
  inputs                Sigma input files ('-' for stdin)

optional arguments:
  -h, --help            show this help message and exit
  --recurse, -r         Use directory as input (recurse into subdirectories is
                        not implemented yet)
  --filter FILTER, -f FILTER
                        Define comma-separated filters that must match (AND-
                        linked) to rule to be processed. Valid filters:
                        level<=x, level>=x, level=x, status=y, logsource=z,
                        tag=t. x is one of: low, medium, high, critical. y is
                        one of: experimental, testing, stable. z is a word
                        appearing in an arbitrary log source attribute. t is a
                        tag that must appear in the rules tag list, case-
                        insensitive matching. Multiple log source
                        specifications are AND linked.
  --target {arcsight,es-qs,es-dsl,kibana,xpack-watcher,elastalert,graylog,limacharlie,logpoint,grep,netwitness,powershell,qradar,qualys,splunk,splunkxml,sumologic,fieldlist,mdatp,devo}, -t {arcsight,es-qs,es-dsl,kibana,xpack-watcher,elastalert,graylog,limacharlie,logpoint,grep,netwitness,powershell,qradar,qualys,splunk,splunkxml,sumologic,fieldlist,mdatp,devo}
                        Output target format
  --target-list, -l     List available output target formats
  --config CONFIG, -c CONFIG
                        Configurations with field name and index mapping for
                        target environment. Multiple configurations are merged
                        into one. Last config is authoritative in case of
                        conflicts.
  --output OUTPUT, -o OUTPUT
                        Output file or filename prefix if multiple files are
                        generated
  --backend-option BACKEND_OPTION, -O BACKEND_OPTION
                        Options and switches that are passed to the backend
  --defer-abort, -d     Don't abort on parse or conversion errors, proceed
                        with next rule. The exit code from the last error is
                        returned
  --ignore-backend-errors, -I
                        Only return error codes for parse errors and ignore
                        errors for rules that cause backend errors. Useful,
                        when you want to get as much queries as possible.
  --verbose, -v         Be verbose
  --debug, -D           Debugging output
```

### Examples

#### Single Rule Translation
Translate a single rule
```
tools/sigmac -t splunk -c splunk-windows rules/windows/sysmon/sysmon_susp_image_load.yml
```
#### Rule Set Translation
Translate a whole rule directory and ignore backend errors (`-I`) in rule conversion for the selected backend (`-t splunk`)
```
tools/sigmac -I -t splunk -c splunk-windows -r rules/windows/sysmon/
```
#### Translate Only Rules of Level High or Critical
Translate a whole rule directory and ignore backend errors (`-I`) in rule conversion for the selected backend (`-t splunk`) and select only rules of level `high` and `critical`
```
tools/sigmac -I -t splunk -c splunk-windows -f 'level>=high' -r rules/windows/sysmon/
```
#### Rule Set Translation with Custom Config
Apply your own config file (`-c ~/my-elk-winlogbeat.yml`) during conversion, which can contain you custom field and source mappings
```
tools/sigmac -t es-qs -c ~/my-elk-winlogbeat.yml -r rules/windows/sysmon
```
#### Generic Rule Set Translation
Use a config file for `process_creation` rules (`-r rules/windows/process_creation`) that instructs sigmac to create queries for a Sysmon log source (`-c tools/config/generic/sysmon.yml`) and the ElasticSearch target backend (`-t es-qs`)
```
tools/sigmac -t es-qs -c tools/config/generic/sysmon.yml -r rules/windows/process_creation
```
#### Generic Rule Set Translation with Custom Config
Use a config file for a single `process_creation` rule (`./rules/windows/process_creation/win_susp_outlook.yml`) that instructs sigmac to create queries for process creation events generated in the Windows Security Eventlog (`-c tools/config/generic/windows-audit.yml`) and a Splunk target backend (`-t splunk`)
```
tools/sigmac -t splunk -c ~/my-splunk-mapping.yml -c tools/config/generic/windows-audit.yml ./rules/windows/process_creation/win_susp_outlook.yml
```
(See @blubbfiction's [blog post](https://patzke.org/a-guide-to-generic-log-sources-in-sigma.html) for more information)

### Supported Targets

* [Splunk](https://www.splunk.com/) (plainqueries and dashboards)
* [ElasticSearch Query Strings](https://www.elastic.co/guide/en/elasticsearch/reference/current/query-dsl-query-string-query.html)
* [ElasticSearch Query DSL](https://www.elastic.co/guide/en/elasticsearch/reference/current/query-dsl.html)
* [Kibana](https://www.elastic.co/de/products/kibana)
* [Elastic X-Pack Watcher](https://www.elastic.co/guide/en/x-pack/current/xpack-alerting.html)
* [Logpoint](https://www.logpoint.com)
* [Microsoft Defender Advanced Threat Protection (MDATP)](https://www.microsoft.com/en-us/microsoft-365/windows/microsoft-defender-atp)
* [Azure Sentinel / Azure Log Analytics](https://azure.microsoft.com/en-us/services/azure-sentinel/)
* [Sumologic](https://www.sumologic.com/)
* [ArcSight](https://software.microfocus.com/en-us/products/siem-security-information-event-management/overview)
* [QRadar](https://www.ibm.com/de-de/marketplace/ibm-qradar-siem)
* [Qualys](https://www.qualys.com/apps/threat-protection/)
* [RSA NetWitness](https://www.rsa.com/en-us/products/threat-detection-response)
* [PowerShell](https://docs.microsoft.com/en-us/powershell/scripting/getting-started/getting-started-with-windows-powershell?view=powershell-6)
* [Grep](https://www.gnu.org/software/grep/manual/grep.html) with Perl-compatible regular expression support
* [LimaCharlie](https://limacharlie.io)
* [ee-outliers](https://github.com/NVISO-BE/ee-outliers)
* [Structured Threat Information Expression (STIX)](https://oasis-open.github.io/cti-documentation/stix/intro.html)
* [LOGIQ](https://www.logiq.ai)
* [uberAgent ESA](https://uberagent.com/)
* [Devo](https://devo.com)
* [LogRhythm](https://logrhythm.com/)
* [Datadog Logs](https://docs.datadoghq.com/logs/explorer/search_syntax/)
* [FortiSIEM](https://docs.fortinet.com)
* [HAWK.io MDR](https://hawk.io/)

New targets are continuously developed. You can get a list of supported targets with `sigmac --lists` or `sigmac -l`.

### Requirements

The usage of Sigmac (the Sigma Rule Converter) or the underlying library requires Python >= 3.5 and PyYAML.

### Installation

It's available on PyPI. Install with:

```bash
pip3 install sigmatools
```

Alternatively, if used from the Sigma Github repository, the Python dependencies can be installed with [Pipenv](https://pypi.org/project/pipenv/).
Run the following command to get a shell with the installed requirements:

```bash
pipenv shell
```

For development (e.g. execution of integration tests with `make` and packaging), further dependencies are required and can be installed with:

```bash
pipenv install --dev
pipenv shell
```

## Sigma2MISP

Import Sigma rules to MISP events. Depends on PyMISP.

Parameters that aren't changed frequently (`--url`, `--key`) can be put without the prefixing dashes `--` into a file
and included with `@filename` as parameter on the command line.

Example:
*misp.conf*:

```apacheconf
url https://host
key foobarfoobarfoobarfoobarfoobarfoobarfoo
```

Load Sigma rule into MISP event 1234:

```bash
sigma2misp @misp.conf --event 1234 sigma_rule.py
```

Load Sigma rules in directory sigma_rules/ into one newly created MISP event with info set to *Test Event*:

```bash
sigma2misp @misp.conf --same-event --info "Test Event" -r sigma_rules/
```

## Evt2Sigma

[Evt2Sigma](https://github.com/Neo23x0/evt2sigma) helps you with the rule creation. It generates a Sigma rule from a log entry.

## Sigma2attack

Generates a [MITRE ATT&CK® Navigator](https://github.com/mitre/attack-navigator/) heatmap from a directory containing sigma rules.

Requirements:

* Sigma rules tagged with a `attack.tXXXX` tag (e.g.: `attack.t1086`)

Usage samples:

```bash
# Use the default "rules" folder
./tools/sigma2attack

# ... or specify your own
./tools/sigma2attack --rules-directory ~/hunting/rules
```

Result once imported in the MITRE ATT&CK® Navigator ([online version](https://mitre-attack.github.io/attack-navigator/enterprise/)):

![Sigma2attack result](./images/sigma2attack.png)

## S2AN

Similar to **Sigma2attack**, [S2AN](https://github.com/3CORESec/S2AN) is a pre-compiled binary for both Windows and GNU/Linux that generates [MITRE ATT&CK® Navigator](https://github.com/mitre/attack-navigator/) layers from a directory of Sigma rules.

S2AN was developed to be used as a standalone tool or as part of a CI/CD pipeline where it can be quickly downloaded and executed without external dependencies.

## Contributed Scripts

The directory `contrib` contains scripts that were contributed by the community:

* `sigma2elastalert.py` is by David Routin: A script that converts Sigma rules to Elastalert configurations. This tool
  uses *sigmac* and expects it in its path.

These tools are not part of the main toolchain and maintained separately by their authors.

# License

The toolchain is licensed under the[GNU Lesser General Public License](https://www.gnu.org/licenses/lgpl-3.0.en.html)