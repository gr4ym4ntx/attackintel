
# UPDATE (26 Nov 2018)
MITRE has deprecated the ATT&CK API functionality and will soon be phasing it out. They have moved to utilizing STIX. My code will be available for reference but you can check out my ATT&CK Intel webapp which is in the preliminary phases of development and offers the same info. The link is below. I'm always looking to improve. Got a suggestion for the webapp, please drop me a suggestion at gr4ym4ntx[at]gmail[dot]com. Enjoy.

- [ATT&CK INTEL Webapp](https://gr4ym4ntx.pythonanywhere.com/)

# ATT&CK Intel
A simple python script to query the MITRE ATT&amp;CK API for tactics, techniques, mitigations, &amp; detection methods for specific threat groups.

# Goals
- Quickly align updated tactics, techniques, mitigation, and detection information from MITRE ATT&CK API for a specific threat
- Brush up on my python skills and get familiar with GIT while drinking coffee

# How To
Use one of two methods:
- If (python3 is installed): 
    - Download script from git
    - `pip3 install -r requirements.txt`
    - `python3 attackintel.py`
- Else: 
    - Cut & paste script from git into your favorite [online python emulator](https://repl.it/languages/python3)
- Select a threat number from the menu to get tactics, techniques, mitigation, and detection information

# Resources
- [MITRE ATT&CK API](https://attack.mitre.org/wiki/Using_the_API)

# Requirements
- Python ver.3+

# Limitations
- Can only select a single threat group at a time
- Information is only displayed to the screen (for now)

# Contribute
- New ideas are great! Got ideas for improvement, submit a PR. Thanks!
