#!/usr/bin/env python3
import importlib.util
import pip
import urllib.parse
import requests
from sys import exit
from termcolor import colored, cprint
from time import sleep

class attackintel():
  """Quickly dump known tactics/techniques of a specific Mitre Threat & find the Mitre detection/mitigation references"""
  
  __version__ = "0.1"
  __author__  = "gr4ym4ntx"
  
  def check_install(self):
    # Check for non-standard packages
    pkgs_req = ['requests','termcolor','time']
    for pkg in pkgs_req:
      spec = importlib.util.find_spec(pkg)
      if spec is None:
        print(pkg + " is not installed \n")
        pip.main(['install',pkg])
        print(pkg + " is now installed \n")
    print('Module check complete.')
  
  def get_URL(self, qry):
    # Build Encoded MITRE Query URL
    cprint("Mitre query built ...", 'green')
    return ('https://attack.mitre.org/api.php?action=ask&format=json&query=' + urllib.parse.quote(qry))

  def get_json(self, URL):
    # Gather returned JSON data from MITRE website
    try:
      requests.get(URL).raise_for_status()
      cprint("Successfully retrieved the info from Mitre", 'cyan')
      return(requests.get(URL).json())
    except requests.exceptions.ConnectionError:
      cprint("Cannot connect. Verify URL is valid and try again ... exiting.", 'red')
      exit()
    except requests.exceptions.HTTPError:  
      err_code = requests.get(URL).status_code
      cprint("Failed to connect to Mitre. Error code {} returned. Try re-running script .. exiting.".format(err_code), 'red')
      exit()
      #self.user_input()
    except:
      cprint("Something happened .. rerun script .. exiting.", 'red')
      exit()

  def get_techniques(self, grp_json, grp):
    idx_json = grp_json['query']['results']['Group/' + grp]['printouts']
    grp_name = idx_json['Has display name'][0]
    if not idx_json['Has alias']:
      alias_array = []
    else:
      alias_array = idx_json['Has alias']
    
    # Gather techniques used by the threat actor & dump into array
    technique_name_array = []
    technique_id_array = []
    for info in idx_json['Has technique']:
      technique_name_array.append(info['displaytitle'])
      technique_id_array.append(info["fulltext"])
    cprint("Got techniques for the threat actor ...", 'green')
    return (grp_name,alias_array,technique_name_array,technique_id_array)

  def get_technique_info(self, tech_arr):
    # Gather returned JSON data for techniques from MITRE
    technique_json = []
    for technique_name in tech_arr:
      technique_qry = '[[Category:Technique]][[Has display name::' + technique_name + ']]|?Has tactic|?Has technical description#-ia|?Has mitigation#-ia|?Has analytic details#-ia'
      technique_json.append(self.get_json(self.get_URL(technique_qry)))
    cprint("Got the Mitre information ... dumping info to screen ...", 'green')
    sleep(3)
    return (technique_json)

  def prt2screen(self, g_name, a_array, t_json, t_id_array, t_name_array):
    cprint("\n" + '******************************* ' + 'THREAT REPORT FOR ' + g_name + ' *******************************' + "\n", 'yellow', attrs=['bold'])
    cprint("Aliases: ", 'yellow')
    for i,v in enumerate(a_array):
      print(a_array[i])
    
    # Handle JSON data for techniques and print description, detection & mitigation info to screen
    for idx,val in enumerate(t_json):
    
      # Ensure values exist in tNameArr & tIDArr arrays
      if not t_id_array[idx] or not t_name_array[idx]:
        print("No techniques available")
      else: 
        cprint("\n" + '******************************* ' + t_id_array[idx] + ": "  + t_name_array[idx] + ' *******************************' + "\n", 'yellow', attrs=['bold'])
      
      # Ensure value exist for technique description
      if not t_json[idx]['query']['results'][t_id_array[idx]]['printouts']['Has tactic']:
        cprint("Tactic: ", 'yellow')
        print ('No tactic available')
      else:
        cprint("Tactic: ", 'yellow')
        print (t_json[idx]['query']['results'][t_id_array[idx]]['printouts']['Has tactic'][0]['fulltext'] + "\n")
      
      # Ensure value exist for technique description
      if not t_json[idx]['query']['results'][t_id_array[idx]]['printouts']['Has technical description']:
        cprint("Description: ", 'yellow')
        print ('No description available')
      else:
        cprint("Description: ", 'yellow')
        print (t_json[idx]['query']['results'][t_id_array[idx]]['printouts']['Has technical description'][0] + "\n")
    
      # Ensure value exist for technique detection
      if not t_json[idx]['query']['results'][t_id_array[idx]]['printouts']['Has analytic details']:
        cprint("Detection Tip(s): ", 'yellow')
        print ("No tips available")
      else:
        cprint("Detection Tip(s): ", 'yellow')
        print (t_json[idx]['query']['results'][t_id_array[idx]]['printouts']['Has analytic details'][0] + "\n")
    
      # Ensure value exist for technique mitigation
      if not t_json[idx]['query']['results'][t_id_array[idx]]['printouts']['Has mitigation']:
        cprint("Mitigation(s): ", 'yellow')
        print ("No mitigation available")
      else:
        cprint("Mitigation(s): ", 'yellow')
        print (t_json[idx]['query']['results'][t_id_array[idx]]['printouts']['Has mitigation'][0] + "\n")

  def logo(self):
    cprint (''' 
  /$$$$$$  /$$$$$$$$ /$$$$$$$$ /$$$      /$$$$$$  /$$   /$$       /$$$$$$             /$$               /$$
 /$$__  $$|__  $$__/|__  $$__//$$ $$    /$$__  $$| $$  /$$/      |_  $$_/            | $$              | $$
| $$  \ $$   | $$      | $$  |  $$$    | $$  \__/| $$ /$$/         | $$   /$$$$$$$  /$$$$$$    /$$$$$$ | $$
| $$$$$$$$   | $$      | $$   /$$ $$/$$| $$      | $$$$$/          | $$  | $$__  $$|_  $$_/   /$$__  $$| $$
| $$__  $$   | $$      | $$  | $$  $$_/| $$      | $$  $$          | $$  | $$  \ $$  | $$    | $$$$$$$$| $$
| $$  | $$   | $$      | $$  | $$\  $$ | $$    $$| $$\  $$         | $$  | $$  | $$  | $$ /$$| $$_____/| $$
| $$  | $$   | $$      | $$  |  $$$$/$$|  $$$$$$/| $$ \  $$       /$$$$$$| $$  | $$  |  $$$$/|  $$$$$$$| $$
|__/  |__/   |__/      |__/   \____/\_/ \______/ |__/  \__/      |______/|__/  |__/   \___/   \_______/|__/ 
\n by gr4ym4ntx\n ver: {0}\n'''.format(self.__version__), 'yellow', attrs=['bold'])

  def menu(self):
    cprint ("\n" + 'THREAT LIST ::', 'yellow', attrs=['bold','underline'])
    cprint ('''
  01 - Axiom, Group 72          11 - PittyTiger           26 - APT18, Threat Group    37 - FIN6                     55 - NEODYMIUM
  02 - Moafee                   12 - Darkhotel                 (TG)-0416, Dynamite    38 - Stealth Falcon           56 - PROMETHIUM
  03 - Cleaver,                 13 - APT30                     Panda                  39 - Suckfly                  57 - APT34
       Threat Group(TG)-2889    14 - Night Dragon         27 - Threat Group (TG)-     40 - Patchwork, Dropping      58 - Charming Kitten 
  04 - Ke3chang                 15 - Taidoor                   3390, Emissary Panda,       Elephant, Chinastrats    59 - Magic Hound, Rocket Kitten, 
  05 - APT12, IXESHE, DynCalc,  16 - APT29, The Dukes          BRONZE UNION           41 - Project Sauron                Operation Saffron Rose,
       Numbered Panda, DNSCALC       Cozy Bear, Cozy Duke 28 - Threat Group (TG)-     42 - MONSOON, Operation            Ajax Security Team, Operation
  06 - APT1, Comment Crew /     17 - DragonOK                  1314                        Hangover                      Woolen-Goldfish, Newscaster,
       Panda / Group            18 - admin@338            29 - Scarlet Mimic          43 - Group5                        Cobalt Gypsy
  07 - APT28, Sednit, Sofacy,   19 - Naikon               30 - Lotus Blossom, Spring  44 - Winnti Group, Blackfly   60 - BRONZE BUTLER, REDBALDKNIGHT,
       Pawn Storm, Fancy Bear,  20 - Equation                  Dragon                 45 - menuPass, Stone Panda,        Tick
       STRONTIUM, Tsar Team,    21 - Molerats, Operation  31 - Dust Storm                  APT10, Red Apollo, CVNX
       Threat Group(TG)-4127         Molerats, Gaza       32 - Lazarus Group, HIDDEN  46 - FIN10
  08 - Carbanak, Anunak,             Cybergang                 COBRA, Guardians of    47 - Gamaredon Group 
       Carbon Spider            22 - APT3, Gothic Panda,       Peace, ZINC, NICKEL    48 - RTM 
  09 - Deep Panda, Shell Crew,       Pirpi, UPS Team,          ACADEMY                49 - Oilrig
       WebMasters, KungFu            Buckeye, Threat      33 - Poseidon Group         50 - APT32, OceanLotus Group  
       Kittens, PinkPanther,         Group (TG)-0110      34 - Sandworm Team, Quedagh 51 - FIN10 
       Black Vine               23 - APT16                35 - Dragonfly, Energetic   52 - CopyKittens
  10 - Turla, Waterbug,         24 - MSUpdater                 Bear                   53 - FIN5
       White Bear               25 - APT17, Deputy Dog    36 - GCMAN                  54 - Sowbug
  ''' + "\n", 'yellow', attrs=['bold'])
  
  def user_input(self):
    selection = ''
    flg = 1 

    while(flg == 1):
      # Verify user input is a digit
      while(selection.isdigit() == False):
        selection = input("Select a threat ID number (e.g. 01-60): ")
  
      # If digit, verify it is in acceptable range and build query portion of URL else try again
      if int(selection) in range(1,10):
        grp_id = 'G000' + str(int(selection))
        grpQry = '[[Has ID::' + grp_id + ']]|?Has display name|?Has technique|?Has alias'
        flg = 0
      elif int(selection) in range(10,61):
        grp_id = 'G00' + selection
        grpQry = '[[Has ID::' + grp_id + ']]|?Has display name|?Has technique|?Has alias'
        flg = 0
      else:
        selection = ''
    return(grp_id,grpQry)
  
  def main(self):
    self.check_install()
    
    # Get ascii art & menu
    self.logo()
    self.menu()
  
    # Handle user input 
    group_id,grp_query = self.user_input()
    
    # Get the Mitre intel 
    grp_URL = self.get_URL(grp_query)
    grp_json = self.get_json(grp_URL)
    group_name,alias_arr,tech_name_array,tech_id_array = self.get_techniques(grp_json,group_id)
    tech_json = self.get_technique_info(tech_name_array)
    
    # Display Mitre intel to screen
    self.prt2screen(group_name,alias_arr,tech_json,tech_id_array,tech_name_array)

attackintel().main()
