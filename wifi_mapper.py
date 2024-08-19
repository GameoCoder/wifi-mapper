#Wifi Network Scanning:
	#-Use a library to scan for nearby WIFI networks-Done
	#-Extract Network details like SSID, BSSID, channel and Signal Strength-Done
#Logging
	#-Store the scanned network data in a log file or database
	#-Include timestamp and location information
#Location Tracking
	#-Use a library to get the device's current location (latitude and longitude)
	#-Associate the location with th scanned network data
#Google Maps Integration:
	#Use the Google Maps API to create a map
	#Mark the locations of scanned networks on the map

import os
import scapy.all as scapy
import netifaces as ni
import logging
from geopy.geocoders import Nominatim
from scapy.layers.dot11 import Dot11, Dot11Beacon

print("Hello World")
for i in ni.interfaces():
	if "wlan" in i:
		interface=i
print(interface)

logging.basicConfig(filename='wifi_networks.log', level=logging.INFO, format='%(asctime)s%(message)s')

def get_current_location():
	geolocator=Nominatim(user_agent='wifi_scanner')
	location = geolocator.get('me')
	return location.address

def sniff_wifi_packets(packet):
	if packet.haslayer(Dot11Beacon):
		ssid = packet.info.decode('utf-8')
		bssid = packet.addr2
		channel = packet.channel
		signal_strength = packet.dBm_AntSignal
		location = get_current_location()
		logging.info(f"SSID: {ssid}, BSSID: {bssid}, Channel: {channel}, Location: {location}")

		print(f"SSID: {ssid}, BSSID: {bssid}, Channel: {channel}, Signal Strength: {signal_strength}")
scapy.sniff(iface=interface,prn=sniff_wifi_packets)