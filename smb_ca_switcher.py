# -*- coding: utf8 -*-
__date__       = "13 March 2018"
__version__    = "1.1"
__license__    = "MIT"
__status__     = "Beta"
__author__     = "Andrew Chung"
__maintainer__ = "Andrew Chung"
__email__      = "acchung@gmail.com"
__credits__    = []
__all__        = []
__copyright__ = """Copyright 2018 Andrew Chung
Permission is hereby granted, free of charge, to any person obtaining a copy of 
this software and associated documentation files (the "Software"), to deal in 
the Software without restriction, including without limitation the rights to 
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies 
of the Software, and to permit persons to whom the Software is furnished to do 
so, subject to the following conditions:
The above copyright notice and this permission notice shall be included in all 
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR 
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, 
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE 
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER 
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, 
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE 
SOFTWARE."""

import sys
import platform
import json
import logging
import optparse
import getpass
import re
import csv
import papi_lite

# Global logging object
l = None
# Global PAPI state dictionary
PAPI_STATE = {}

MAX_RECORDS_LIMIT = 1000
URL_PAPI_SMB_SHARES = '3/protocols/smb/shares'
URL_PAPI_ZONES = '3/zones'
NORMAL_SHARE_STRING = '[NORMAL_SHARES]'
CA_SHARE_STRING = '[CA_SHARES]'
CSV_FIELDS_1 = ['zone', 'name', 'path', 'desc']
RENAME_SUFFIX = '_todelete'

def AddParserOptions(parser):
  """Add all the options to an OptParse object
  
  Modifies the passed in OptParrse object itself"""
  parser.add_option("-u", "--user",
                    default=None,
                    help="User name for API authentication.\n"
                      "(default: <Current user>)"
                    )
  parser.add_option("-p", "--password",
                    default=None,
                    help="User password")
  parser.add_option("-s", "--server",
                    default=None,
                    help="Server and port to connect. If running on cluster you can use 127.0.0.1:8080")
  parser.add_option("-i", "--input",
                    default=None,
                    help="Path and file name to an input file with shares.\n"
                      "(default: %default)")
  parser.add_option("-o", "--output",
                    default=None,
                    help="Path and file name to an output file to be written with share information.\n"
                      "(default: <Standard out>)")
  parser.add_option("--ignore_mismatch",
                    action="store_true",
                    default=False,
                    help="Allow updating SMB shares even when input file does not match with existing config.")
  group = optparse.OptionGroup(parser, "Logging and debug options")
  parser.add_option("--pretend",
                    action="store_true",
                    default=False,
                    help="When this flag is enabled, the script will only output what it would do.")
  group.add_option("-l", "--log",
                    default=None,
                    help="Full path and file name for log output.  If not set"
                      "no log output to file will be generated.")
  group.add_option("--console_log",
                    action="store_true",
                    default=False,
                    help="When this flag is set, log output to console. (Default: True if no other logging enabled and quiet is False)")
  group.add_option("-q", "--quiet",
                    action="store_true",
                    default=False,
                    help="When this flag is set, do not log output to console.")
  group.add_option("--debug",
                    default=0,
                    action="count",
                    help="Add multiple debug flags to increase debug. Warning are printed automatically unless suppressed by --quiet.\n"
                      "1: Info, 2: Debug")
  parser.add_option_group(group)

def filter_data(data, type, clone=False):
  """Remove any keys that are invalid as input to the OneFS PAPI. Removal is
  performed based on the type, a plain text string, passed in."""
  if clone:
    d = dict(data)
  else:
    d = data
  if type == 'create_smb_share':
    del d['id']
    del d['zid']
  return d
  
def get_zones(state):
  """Returns all the configured Access Zones on an Isilon cluster."""
  response = papi_lite.rest_call(state, URL_PAPI_ZONES)
  zones = {}
  if response and response[0] == 200:
    json_data = response[2]
    zones = sorted(json_data['zones'], key=lambda x: x['id'])
  else:
    raise Exception('Unable to gather access zones from cluster')
  return zones
  
def get_smb_shares(state):
  """Returns all the configured SMB shares, in all zones on an Isilon cluster as
  an array of dictionaries.
  
  Each entry consists of:
  
  name: Name of the share
  zone: Name of the access zone the share belongs. There is always at least
    one zone.
  path: Path on the file system
  desc: Text description of the share if one exists
  ca: Boolean flag for SMB3 continuous availability support.
  raw: Raw dictionary of all share configuration from OneFS
  """
  zone_shares = []
  
  zones = get_zones(state)
  for zone in zones:
    q_args = {
      'zone': str(zone['id']),
      'resolve_names': 'False',
      'limit': str(MAX_RECORDS_LIMIT),
    }
    response = papi_lite.rest_call(state, URL_PAPI_SMB_SHARES, query_args=q_args)
    l.debug(response)
    if response and response[0] == 200:
      json_data = response[2]
      shares = sorted(json_data['shares'], key=lambda x: x['name'])
      for share in shares:
        zone_shares.append({
          'name': share['name'],
          'zone': zone['id'],
          'path': share['path'],
          'desc': share['description'],
          'ca': share['continuously_available'],
          'raw': share,
        })
    else:
      raise Exception('Unable to get shares for zone: %s'%zone['id'])
  return zone_shares
  
def create_share(state, share, options):
  """Create an SMB share on OneFS
  Requires a dictionary representing a share with the following fields:
  
  name: Name of the SMB share
  zone: Name of the access zone the share will belongs
  raw: A dictionary with all the options for the share. This should have the same
    information that you would get from get_smb_shares.
    
  This function does filter the share configuration before sending it to OneFS."""
  l.info("Creating share: %s - %s, CA: %s"%(share['zone'], share['name'], share['raw']['continuously_available']))
  if not options.pretend:
    data = filter_data(share['raw'], 'create_smb_share')
    response = papi_lite.rest_call(state, URL_PAPI_SMB_SHARES, method='POST', body=json.dumps(data), query_args={'zone': share['zone']})
    l.debug(response)
    if response and response[0] == 201:
      l.info("Share created")
  
def rename_share(state, share, new_name, options):
  """Renames an SMB share so that it has a special suffix
  
  The share should be a dictionary with the following keys:
  
  name: Name of the SMB share
  zone: Name of the access zone the share belongs"""
  l.info("Renaming share: %s - %s, CA: %s to %s"%(share['zone'], share['name'], share['raw']['continuously_available'], new_name))
  if not options.pretend:
    data = {'name': new_name}
    response = papi_lite.rest_call(state, '%s/%s'%(URL_PAPI_SMB_SHARES, share['name'].encode('utf-8')), method='PUT', body=json.dumps(data), query_args={'zone': share['zone'].encode('utf-8')})
    l.debug(response)
    if response and response[0] == 204:
      l.info("Share renamed")
  
def delete_share(state, share, options):
  """Deletes an SMB share from OneFS.
  
  The share should be a dictionary with the following keys:
  
  name: Name of the SMB share
  zone: Name of the access zone the share belongs"""
  l.info("Deleting share: %s - %s, CA: %s"%(share['zone'], share['name'], share['raw']['continuously_available']))
  if not options.pretend:
    response = papi_lite.rest_call(state, '%s/%s'%(URL_PAPI_SMB_SHARES, share['name'].encode('utf-8')), method='DELETE', query_args={'zone': share['zone'].encode('utf-8')})
    l.debug(response)
    if response and response[0] == 204:
      l.info("Share deleted")
  
def update_smb_shares(shares, cur_shares, cur_ca_shares, tgt_shares, tgt_ca_shares, options):
  """Given 4 lists of SMB shares, this function deletes and recreates the shares
  to change the continuous availability feature.
  
  The 4 lists required are:
  cur_shares: Current SMB shares without CA enabled
  cur_ca_shares: Current SMB shares with CA enabled
  tgt_shares: List of all shares we want to have CA disabled
  tgt_ca_shares: List of all shares we want to have CA enabled
  
  Shares in the current lists require the 'name', 'zone', 'path' and 'raw' keys.
  Shares in the target list can consist of only the 'name', 'zone' and 'path' keys"""
  to_ca_list = []
  to_smb_list = []
  extra_smb_list = []
  extra_ca_list = []
  for x in tgt_shares:
    found = False
    for y in cur_shares:
      if x['zone'] == y['zone'] and x['name'] == y['name'] and x['path'] == y['path']:
        # The shares match
        l.debug("Share match found: %s"%x)
        cur_shares.remove(y)
        found = True
        break
    if found:
      continue
    for y in cur_ca_shares:
      if x['zone'] == y['zone'] and x['name'] == y['name'] and x['path'] == y['path']:
        # The shares match but it needs a change of CA status
        l.debug("CA share to non-CA share found: %s"%x)
        to_smb_list.append(y)
        cur_ca_shares.remove(y)
        found = True
        break
    if found:
      continue
    extra_smb_list.append(x)
    
  for x in tgt_ca_shares:
    found = False
    for y in cur_shares:
      if (x['zone'] == y['zone']) and (x['name'] == y['name']) and (x['path'] == y['path']):
        # The shares match but it needs a change of CA status
        l.debug("Non-CA share to CA share found: %s"%x)
        to_ca_list.append(y)
        cur_shares.remove(y)
        found = True
        break
    if found:
      continue
    for y in cur_ca_shares:
      if (x['zone'] == y['zone']) and (x['name'] == y['name']) and (x['path'] == y['path']):
        # The shares match
        l.debug("CA share match found: %s"%x)
        cur_ca_shares.remove(y)
        found = True
        break
    if found:
      continue
    extra_ca_list.append(x)
  
  # Output a bunch of information about what we processed
  log_lev = logging.DEBUG
  mismatch = False
  if options.pretend:
    l.log(100, "Only pretending to update shares")
  l.log(log_lev, "Shares that need to disable CA: %s"%to_smb_list)
  l.log(log_lev, "Shares that need to enable CA: %s"%to_ca_list)
  if not options.ignore_mismatch:
    log_lev = logging.CRITICAL
  if extra_smb_list:
    l.log(log_lev, "Shares in input file not found in current system: %s"%extra_smb_list)
    mismatch = True
  if extra_ca_list:
    l.log(log_lev, "CA shares in input file not found in current system: %s"%extra_ca_list)
    mismatch = True
  if cur_shares:
    l.log(log_lev, "Shares on system not found in input file: %s"%cur_shares)
    mismatch = True
  if cur_ca_shares:
    l.log(log_lev, "CA shares on system not found in input file: %s"%cur_shares)
    mismatch = True
  if mismatch:
    if not options.ignore_mismatch:
      raise Exception("Share mismatches found. Please correct or add --ignore_mismatch flag.")
    else:
      l.warn("Share mismatches found. Processing shares from input file only.")
  # Do the actual work of deleting a share then recreating it with the CA flag flipped
  for x in to_smb_list:
    new_name = x['name'] + RENAME_SUFFIX
    rename_share(PAPI_STATE, x, new_name, options)
    x['raw']['continuously_available'] = False
    create_share(PAPI_STATE, x, options)
    x['name'] = new_name
    delete_share(PAPI_STATE, x, options)
  for x in to_ca_list:
    new_name = x['name'] + RENAME_SUFFIX
    rename_share(PAPI_STATE, x, new_name, options)
    x['raw']['continuously_available'] = True
    create_share(PAPI_STATE, x, options)
    x['name'] = new_name
    delete_share(PAPI_STATE, x, options)
  
def parse_input_init(state):
  """Initialize a state object for the input parser"""
  state.clear()
  state['sm'] = 'IDLE'
  
def parse_input(line, state, data):
  """Parse a single line from an input text file with a list of CA and non CA SMB shares.
  The input file should have 2 sections and below each section one share per line.
  
  Example:
  [NORMAL_SHARES]
  System,TestShare1,/ifs,
  AnotherZoneName,TestShare2,/ifs/data,Optional description of share in AnotherZoneName

  [CA_SHARES]
  System,ifs,/ifs,Isilon OneFS
  TestZone,TestShare,/ifs/testzone,This share should be a CA enabled share
  """
  l.debug("Read line: %s"%line)
  tok = line.strip()
  if len(tok) == 0:
    return
  if NORMAL_SHARE_STRING in tok:
    state['sm'] = 'NORMAL'
    return
  elif CA_SHARE_STRING in tok:
    state['sm'] = 'CA'
    return
  
  l.debug(state)
  if state['sm'] == 'IDLE':
    l.debug("Unparsed line: %s"%tok)
  elif state['sm'] == 'NORMAL':
    l.debug("Parsing normal share: %s"%tok)
    obj = csv.DictReader([tok], fieldnames=CSV_FIELDS_1)
    data['shares'].append(obj.next())
  elif state['sm'] == 'CA':
    l.debug("Parsing CA share: %s"%tok)
    obj = csv.DictReader([tok], fieldnames=CSV_FIELDS_1)
    data['ca_shares'].append(obj.next())    
  else:
    raise Exception('Invalid state for the input parser: %s'%state['sm'])
  
def main():
  global l
  global PAPI_STATE
  
  USAGE =  "usage: %prog [options]"
  DEFAULT_LOG_FORMAT = '%(asctime)s - %(module)s|%(funcName)s - %(levelname)s [%(lineno)d] %(message)s'

  # Create our command line parser. We use the older optparse library for compatibility on OneFS
  parser = optparse.OptionParser(usage=USAGE, version=u"%prog v" + __version__ + " (" + __date__ + ")")
  AddParserOptions(parser)
  (options, args) = parser.parse_args(sys.argv[1:])
  if (options.log is None) and (not options.quiet):
    options.console_log = True
    
  # Setup logging
  l = logging.getLogger()
  debug_count = options.debug
  if debug_count > 1:
    l.setLevel(logging.DEBUG)
  elif debug_count > 0:
    l.setLevel(logging.INFO)
  elif not options.quiet:
    l.setLevel(logging.WARNING)
  if options.console_log:
    log_handler = logging.StreamHandler()
    log_handler.setFormatter(logging.Formatter(DEFAULT_LOG_FORMAT))
    l.addHandler(log_handler)
  if options.log:
    log_handler = logging.FileHandler(options.log)
    log_handler.setFormatter(logging.Formatter(DEFAULT_LOG_FORMAT))
    l.addHandler(log_handler)
  if (options.log is None) and (options.console_log is False):
    l.addHandler(logging.NullHandler())
  
  papi_lite.init_papi_state(PAPI_STATE)
  
  l.debug(platform.system())
  if options.server:
    PAPI_STATE['ONCLUSTER'] = False
  elif "OneFS" in platform.system():
    PAPI_STATE['ONCLUSTER'] = True
  if not PAPI_STATE['ONCLUSTER']:
    if options.user:
      PAPI_STATE['USER'] = options.user
    else:
      l.info("Using default user: %s\n"%PAPI_STATE['USER'])
      PAPI_STATE['USER'] = getpass.getuser()
    if options.password:
      PAPI_STATE['PASSWORD'] = options.password
    else:
      PAPI_STATE['PASSWORD'] = getpass.getpass()
    PAPI_STATE['SERVER'] = options.server

  # Read all SMB shares from an Isilon cluster and break them into a list of CA and non-CA shares
  shares = get_smb_shares(PAPI_STATE)
  non_ca_shares = []
  ca_shares = []
  for share in shares:
    if share['ca']:
      ca_shares.append(share)
    else:
      non_ca_shares.append(share)
  
  if options.input:
    # If an input file is being specified then we will switch to a mode where
    # we try to change the SMB shares on a cluster to match the input file
    l.info("Reading input file: %s"%options.input)
    file_shares = []
    file_ca_shares = []
    with open(options.input) as f:
      state = {}
      parse_input_init(state)
      for line in f:
        parse_input(line, state, {'shares': file_shares, 'ca_shares': file_ca_shares})
      l.debug("Parsed standard shares: %s"%file_shares)
      l.debug("Parsed CA shares: %s"%file_ca_shares)
    try:
      update_smb_shares(shares, non_ca_shares, ca_shares, file_shares, file_ca_shares, options)
    except Exception as e:
      sys.stderr.write(str(e))
      sys.stderr.write("\n")
      sys.exit(1)
  else:
    # This section handles dumping the cluster read SMB shares to a file for user editing
    # The output file should then be used as the input file for this script
    if options.output is None:
      ofile = sys.stdout
    else:
      ofile = open(options.output, "wb")
    ofile.write('%s\n'%NORMAL_SHARE_STRING)
    writer = csv.DictWriter(ofile, fieldnames=CSV_FIELDS_1, extrasaction='ignore')
    for share in non_ca_shares:
      writer.writerow(share)
    ofile.write('\n%s\n'%CA_SHARE_STRING)
    for share in ca_shares:
      writer.writerow(share)
    ofile.close()
    
# __name__ will be __main__ when run directly from the Python interpreter.
# __file__ will be None if the Python files are combined into a ZIP file and executed there
if __name__ == "__main__":
  main()
