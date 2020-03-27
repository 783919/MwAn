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

BANNER="Android Package Pull rel. 0.0.0 by Corrado Federici (corrado.federici@unibo.it). Times are in GMT"
PACKAGE_HASH_LIST_FILE="packages_sha1.txt"
#############################################################################################
def pull_android_packages(dest_folder):
  processed_packages=0
  pulled_packages=0
  try:
    packages_line=subprocess.run(["adb", "shell", "pm", "list", "packages" ,"-f"],
      capture_output=True,text=True)
    if len(packages_line.stderr)>0 or not packages_line.stdout.startswith("package:"):
      raise Exception("Adb package listing failed. Ensure that phone is in DEBUG mode and debugging is authorized. Error: {0}".format(packages_line.stderr))
    packages = packages_line.stdout.splitlines()
    for package in packages:
      processed_packages+=1
      right=package[len("package:"):]
      head,sep,pack_name=right.partition(".apk=")
      pack_path=head + ".apk"
      logging.info("Pulling {0} to destination folder {1}".format(pack_path,dest_folder))
      dest_path=os.path.join(dest_folder,pack_name + ".apk")
      pull_line=subprocess.run(["adb", "pull", pack_path,dest_path],capture_output=True,text=True)
      if "error" in pull_line.stdout or not "1 file pulled" in pull_line.stdout:
        logging.error("Cannot copy package {0}. Error: {1}".format(pack_path,pull_line.stdout))
      else:
        pulled_packages+=1
        h=hashlib.sha1()
        f = open(dest_path, "rb")
        h.update(f.read())
        sha1=h.hexdigest()
        f.close()
        g=open(PACKAGE_HASH_LIST_FILE,"a")
        g.write(sha1 + "\t" + pack_name + ".apk" +"\n")
        g.close()
    logging.info("Done pulling {0} packages out of {1}".format(pulled_packages,processed_packages))
  except Exception as ex:
    output=logging.error("An error occurred. {0}".format(ex.args))
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
  if len(sys.argv)!=2:
    raise Exception("Usage: {0} <path to folder where storing pulled packages>".format(sys.argv[0])) 
  dest_folder=sys.argv[1]
  if not(os.path.exists(dest_folder)):
    os.makedirs(dest_folder)
  else:
    for filename in os.listdir(dest_folder):
      os.remove(os.path.join(dest_folder,filename))
  g = open(PACKAGE_HASH_LIST_FILE,"w")
  g.write("SHA1"+"\t"+"PACKAGE NAME"+"\n")
  g.close()
  pull_android_packages(dest_folder)
except Exception as ex:
  logging.error("An error occurred. {0}".format(ex.args))

