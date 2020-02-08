
import os

RUNNING_PATH = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT_PATH = os.path.join(RUNNING_PATH, 'script')
LOG_PATH = os.path.join(RUNNING_PATH, 'scanner/logs/')
# configuration
CHECK_CONF_FILE = os.path.join(RUNNING_PATH, 'conf/', 'conf.json')
DEFAULT_CONF_FILE = os.path.join(RUNNING_PATH, 'conf/default', 'conf_default.json')
# essential methods/functions in custom scripts/PoC (such as function poc())
ESSENTIAL_MODULE_METHODS = ["poc"]
# essential valuables that have to be defined (such as "poc_info")
ESSENTIAL_POC_INFO = ["poc_info"]
ESSENTIAL_VALUABLES = ["poc_info['poc']", "poc_info['poc']['Name']","poc_info['vul']", "poc_info['vul']['Product']", "poc_info['vul']['Severity']"]
# 默认加载的pocs
DEFAULT_POCS_PATH = os.path.join(RUNNING_PATH, 'conf/default', 'pocs_default.json')

# Web
SESSION_CONF_FILE = os.path.join(RUNNING_PATH, 'conf/web/', 'session')
CONF_PATH = os.path.join(RUNNING_PATH, 'conf/')