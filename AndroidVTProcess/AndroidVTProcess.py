
import subprocess
import os
import sys
import ctypes
import winreg
import time
import json
import re
import logging
import hashlib
import requests

BANNER="Android Virus Total Analyzer rel. 0.0.0 by corrado.federici@unibo.it. Times are in GMT"
#Optional lookup of NIST good files hash list (GFHL)
#First line of file is header: 
#"SHA-1","MD5","CRC32","FileName","FileSize","ProductCode","OpSystemCode","SpecialCode"
USE_NIST_GFHL=True
NIST_GFHL_FNAME="Hash_Android_RDS_v.2.67.txt"
NIST_GFHL_DELIM="[',']{1}"
NIST_GFHL_SHA1_POS=0
NIST_GFHL_FNAME_POS=3
NIST_GFHL_ALLOWED_FILE_EXT=("apk")
#Already checked packages (ACP). We keep track of mobile phone packages already checked just not to repeat
#from start if malware analysis process interrupts
ACP_FNAME="checked_packages.txt"
#final report file name
REPORT_FNAME="report.txt"
SHA1_MATCH="^([a-fA-F0-9]{40})$"
VT_API_KEY_MATCH="^([a-fA-F0-9]{64})$"
VT_API_KEY=""
VT_FILE_REPORT_URL="https://www.virustotal.com/vtapi/v2/file/report"
POSITIVE_RES="positive"
NEGATIVE_RES="negative"
UNKNOWN_RES="unknown"

##############################################################################
def send_data_to_vt(url,params):
  tx_ok=False
  r = requests.get(url,params)
  if r.status_code==200:
  # extracting data in json format
    tx_ok=True
    return tx_ok,r.json()
  elif r.status_code==204:
    logging.warning("Response delayed by VT server")
    #delay=(1,2,4,8,16,32,64)# exponential delay retry policy 
    delay=(60,120,180)# doubling time delay retry policy
    #delay=(5,5,5,5,5,5,5,5,5,5,5,5,5)#set tuple members according to desired retry policy 
    for dly in delay:
      logging.warning("Retrying after {0} seconds...".format(dly))
      time.sleep(dly)
      r = requests.get(url,params)
      if r.status_code==200:
        tx_ok=True
        return tx_ok,r.json()
      elif r.status_code==204:
        logging.warning("Response delayed by VT server")
        continue
      else:
        logging.error("Fatal error while talking to Virus Total. Code:{0}".format(r.status_code))
        break
    logging.error("Too many tx retries. Virus Total Server too busy")
  else:
    logging.error("Fatal error while talking to Virus Total. Code:{0}".format(r.status_code))
  data={}
  return tx_ok,data

###############################################################################
def parse_vt_response(resp):
  ismatch=False
  isunknown=False
  if resp["response_code"]==0:
    isunknown=True
    logging.info("Hash not present in VT database")
    logging.debug("Response: {0}".format(resp["verbose_msg"]))
  elif resp["positives"]==0:
    logging.info(
      "No VT engine detected hash as a malware. Total: {0}, Positives: {1}, Link: {2}".
      format(resp["total"],resp["positives"],resp["permalink"]))
  else:
    ismatch=True
    logging.info("Positive MATCH !!! {0} engines out of {1} detected hash as a malware. Link: {2}".format(
      resp["positives"],resp["total"],resp["permalink"]))
  return ismatch,isunknown

#############################################################################################
def process_android_packages(sha1_list_file,nist_good_file_hash_list,
  already_checked_file_hash_list):
  processed_hashes=0
  pos_matches=0
  negatives=0
  unknown=0
  try:
    f = open(sha1_list_file, "r")
    for line in f:
      cols=re.split("\t",line.replace('\n', ''))
      sha1=cols[0]
      package=cols[1]
      processed_hashes+=1
      if len(already_checked_file_hash_list)>0:
        if sha1 in already_checked_file_hash_list:
          logging.info("Package {0} already checked. No need to query Virus Total".format(package))
          r = open(REPORT_FNAME,"a")
          r.write(sha1+"\t"+already_checked_file_hash_list[sha1]+"\n")
          r.close()
          res=re.split("\t",already_checked_file_hash_list[sha1].replace('\n', ''))
          if res[1]==POSITIVE_RES:
            pos_matches+=1
          elif res[1]==NEGATIVE_RES:
            negatives+=1
          else:
            unknown+=1
          continue
      if USE_NIST_GFHL:
        if sha1 in nist_good_file_hash_list:
          logging.info("Package {0} is in NIST good files hash list. No need to query Virus Total".format(package))
          r = open(REPORT_FNAME,"a")
          r.write(sha1+"\t"+nist_good_file_hash_list[sha1]+NEGATIVE_RES+"\n")
          r.close()
          negatives+=1
          continue
      logging.info("Querying Virus Total for package {0} with SHA1 hash: {1}...".format(package,sha1))
      PARAMS = {'apikey':VT_API_KEY,'resource':sha1}
      tx_ok,data=send_data_to_vt(VT_FILE_REPORT_URL,PARAMS)
      if tx_ok:
        ismatch,isunknown=parse_vt_response(data)
        result=""
        if ismatch:
          pos_matches+=1#package detected as malware
          result=POSITIVE_RES
        elif not isunknown:#update list of already checked good packages
          result=NEGATIVE_RES
          negatives+=1
        else:
          result=UNKNOWN_RES
          unknown+=1
        g=open(ACP_FNAME,"a")
        g.write(sha1+"\t"+package+"\t"+result+"\n")
        g.close()
        r = open(REPORT_FNAME,"a")
        r.write(sha1+"\t"+package+"\t"+result+"\n")
        r.close()
      time.sleep(2)
    logging.info("Done. Processed packages: {0} . Positives: {1} Negatives: {2} Unknown: {3}".format(
      processed_hashes,pos_matches,negatives,unknown))
    f.close()
  except Exception as ex:
    output=logging.error("An error occurred. {0}".format(ex.args))
############################################################################################
def read_nist_good_hl_file():
  line_num=0
  gfhl={}
  f = open(NIST_GFHL_FNAME, "r")
  for line in f:
    if line_num==0:#ignore header
      line_num+=1
      continue
    if line.startswith("#"):#ignore comments
      line_num+=1
      continue
    cols=re.split(NIST_GFHL_DELIM,line.replace('"', ''))
    gfhl_sha1=cols[NIST_GFHL_SHA1_POS]
    gfhl_fname=cols[NIST_GFHL_FNAME_POS]
    if re.match(SHA1_MATCH,gfhl_sha1) and gfhl_fname.endswith(NIST_GFHL_ALLOWED_FILE_EXT):
      gfhl[gfhl_sha1]=gfhl_fname
  f.close()
  return gfhl

############################################################################################
def read_already_checked_packages_file():
  cgphl={}
  if os.path.isfile(ACP_FNAME):
    f = open(ACP_FNAME, "r")
    for line in f:
      cols=re.split("\t",line.replace('\n', ''))
      cgphl[cols[0]]=cols[1]+"\t"+cols[2]
    f.close()
  return cgphl

############################################################################################
#main
try:
  logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
      logging.FileHandler('log.txt','a'),#append is default anyway
      logging.StreamHandler()
      ])
  logging.Formatter.converter = time.gmtime
  logging.info(BANNER)
  if len(sys.argv)!=3:
    raise Exception("Usage: {0} <path to packages sha1 list file> <Virus Total API key>".
      format(sys.argv[0])) 
  sha1_list_file=sys.argv[1]
  if not(os.path.exists(sha1_list_file)):
    raise Exception("Path {0} is invalid".format(sha1_list_file))
  VT_API_KEY=sys.argv[2]
  if not re.match(VT_API_KEY_MATCH,VT_API_KEY):
    raise Exception("VT_API_KEY syntax is not valid. Valid Virus Total api keys are 64 hex chars")
  if len(NIST_GFHL_ALLOWED_FILE_EXT)==0:
    raise Exception("Specify at least one file extension")
  if os.path.exists(REPORT_FNAME):
    os.remove(REPORT_FNAME)
  nist_good_file_hash_list={}
  already_checked_files=read_already_checked_packages_file()
  if USE_NIST_GFHL:
    nist_good_file_hash_list=read_nist_good_hl_file()
  process_android_packages(sha1_list_file,nist_good_file_hash_list,already_checked_files)
except Exception as ex:
  logging.error("An error occurred. {0}".format(ex.args))

