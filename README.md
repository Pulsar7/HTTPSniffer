# HTTPSniffer
Ein Python3-Script, welches an Port 80 nach Passwörtern oder/und Benutzernamen sucht.

# Betriebssystem
Ein dafür am Besten geeignetes Betriebssystem ist Linux.
Sollte die Benutzung von einem Handy bevorzugt werden, mit zum Beispiel dem Tool Termux, dann muss dieser über 
Root-Rechte verfügen. Sollte dies nicht der Fall sein, kann das Modul Scapy nicht ausgeführt werden.

# Python-Module

    -> colorama (from colorama import Fore,Style) 
    -> os (import os)
    -> datetime (from datetime import datetime)
    -> sys (import sys)
    -> scapy (from scapy.all import *)
    
# Bekanntes Windows Problem

Bei der Benutzung von dem Modul 'colorama', kann ein Problem bei den Windows-Betriebssystemen 
in Erscheinung treten, dass die Farben bei der Konsole nicht angezeigt werden können. Dies kann man mit einer simplen Änderung des Scripts regeln:
  
     from colorama import Fore,Style,init
     init()

# Was macht das Script?

Das Script 'hört' am Port 80 bei einer beliebigen und sich im lokalen Netzwerk befindenden Ziel-IP zu und achtet direkt auf die im Script gespeicherten 
Schlüsselwörter. (Passwörter und Benutzernamen) (Das Script kann aber nur Passwörter und Benutzernamen von HTTP-Seiten abgreifen, nicht an SSL verschlüsselten Seiten.)
     
