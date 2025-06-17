#!/usr/bin/python3

import requests
from datetime import datetime
import json
import paho.mqtt.client as mqtt
import base64
import random
import time
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from meshtastic import (
    mesh_pb2,
    mqtt_pb2,
    portnums_pb2,
    telemetry_pb2,
    BROADCAST_NUM,
)

# --- Configuration ---
API_BASE_URL = "https://api.met.gov.my/v2.1/data"
API_TOKEN = "YOURTOKEN"

# MQTT Configuration
MQTT_BROKER = "mqtt.lucifernet.com"
MQTT_PORT = 1883
MQTT_USERNAME = "meshdev"
MQTT_PASSWORD = "large4cats"

# Meshtastic Configuration
# Define your encryption key
key = "1PG7OiApB1nwvP+rz05pAQ=="  # Replace with your actual key THIS IS THE AQ== default key for LongFast
padded_key = key.ljust(len(key) + ((4 - (len(key) % 4)) % 4), "=")
replaced_key = padded_key.replace("-", "+").replace("_", "/")
key = replaced_key

root_topic = "msh/MY_919/2/e/"
channel = "LongFast"

# Fixed node ID as requested - !xxxxx
NODE_ID = 0xb03dAAAA
PACKET_ID = random.randint(1, 0xFFFFFFFF)

# Weather code mapping
WEATHER_CODE_MAP = {
    'tstorm': 'Thunderstorms',
    # Add more mappings as needed
}

def xor_hash(data):
    """XOR hash function used by Meshtastic"""
    result = 0
    for char in data:
        result ^= char
    return result

def generate_hash(name, key):
    """Generate hash for channel name and key - based on Meshtastic implementation"""
    replaced_key = key.replace("-", "+").replace("_", "/")
    key_bytes = base64.b64decode(replaced_key.encode('ascii'))
    h_name = xor_hash(bytes(name, 'utf-8'))
    h_key = xor_hash(key_bytes)
    result = h_name ^ h_key
    return result

def encrypt_message(channel, key, mesh_packet, encoded_message):
    """Encrypt message using Meshtastic's encryption method"""
    try:
        # Generate channel hash
        mesh_packet.channel = generate_hash(channel, key)
        
        # Decode the key
        key_bytes = base64.b64decode(key.encode('ascii'))
        
        # Create nonce from packet ID and from node
        nonce_packet_id = getattr(mesh_packet, "id").to_bytes(8, "little")
        nonce_from_node = getattr(mesh_packet, "from").to_bytes(8, "little")
        nonce = nonce_packet_id + nonce_from_node
        
        # Encrypt using AES-CTR
        cipher = Cipher(algorithms.AES(key_bytes), modes.CTR(nonce), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_bytes = encryptor.update(encoded_message.SerializeToString()) + encryptor.finalize()
        
        # Set the encrypted data
        mesh_packet.encrypted = encrypted_bytes
        
        print(f"Message encrypted successfully")
        print(f"  Channel hash: {mesh_packet.channel}")
        print(f"  Encrypted size: {len(encrypted_bytes)} bytes")
        
        return encrypted_bytes
        
    except Exception as e:
        print(f"Encryption failed: {str(e)}")
        return None

def create_service_envelope(mesh_packet, channel_id, gateway_id):
    """Creates a ServiceEnvelope for MQTT publishing - based on official examples"""
    service_envelope = mqtt_pb2.ServiceEnvelope()
    
    # Copy the packet
    service_envelope.packet.CopyFrom(mesh_packet)
    
    # Set channel_id - just the channel name
    service_envelope.channel_id = channel_id
    
    # Set gateway_id - the node ID in !xxxxxxxx format
    service_envelope.gateway_id = gateway_id
    
    print(f"Created ServiceEnvelope:")
    print(f"  Channel ID: '{service_envelope.channel_id}'")
    print(f"  Gateway ID: '{service_envelope.gateway_id}'")
    
    return service_envelope

def generate_mesh_packet(destination_id, encoded_message):
    """Generate MeshPacket - based on official examples"""
    global PACKET_ID
    
    mesh_packet = mesh_pb2.MeshPacket()
    
    # Set packet ID and increment for next message
    mesh_packet.id = PACKET_ID
    PACKET_ID += 1
    
    # Set from node
    setattr(mesh_packet, 'from', NODE_ID)
    
    # Set destination
    mesh_packet.to = destination_id
    
    # Set other fields as per official examples
    mesh_packet.want_ack = False
    mesh_packet.hop_limit = 7
    mesh_packet.hop_start = 1
    
    # Set timestamp
    mesh_packet.rx_time = int(time.time())
    
    print(f"Created MeshPacket:")
    print(f"  ID: {mesh_packet.id}")
    print(f"  From: !{getattr(mesh_packet, 'from'):08x}")
    print(f"  To: {mesh_packet.to}")
    
    return mesh_packet

def publish_mqtt_message(weather_string):
    """Publish encrypted message to MQTT broker"""
    try:
        print(f"Encrypting message: '{weather_string}'")
        
        # Create Data message
        data_message = mesh_pb2.Data()
        data_message.portnum = portnums_pb2.TEXT_MESSAGE_APP
        data_message.payload = weather_string.encode('utf-8')
        
        # Create MeshPacket
        mesh_packet = generate_mesh_packet(BROADCAST_NUM, data_message)
        
        # Encrypt the message
        encrypted_bytes = encrypt_message(channel, key, mesh_packet, data_message)
        if encrypted_bytes is None:
            print("Failed to encrypt message")
            return
        
        # Create ServiceEnvelope with proper gateway ID
        gateway_id = f"!{NODE_ID:08x}"
        service_envelope = create_service_envelope(mesh_packet, channel, gateway_id)
        
        # Serialize the service envelope
        serialized_envelope = service_envelope.SerializeToString()
        
        # Create the complete MQTT topic with node ID
        mqtt_topic = f"{root_topic}{channel}/!{NODE_ID:08x}"
        
        print(f"Attempting to publish encrypted message to topic '{mqtt_topic}'")
        print(f"Encrypted payload size: {len(serialized_envelope)} bytes")
        
        # Show the last 30 bytes for debugging
        last_bytes = serialized_envelope[-30:]
        hex_str = ' '.join(f'{b:02x}' for b in last_bytes)
        ascii_str = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in last_bytes)
        print(f"Last 30 bytes (hex): {hex_str}")
        print(f"Last 30 bytes (ascii): {ascii_str}")
        
        # Publish the encrypted message
        client.publish(mqtt_topic, serialized_envelope, qos=1)
        
    except Exception as e:
        print(f"Failed to publish message: {str(e)}")

# MQTT callback functions
def on_connect(client, userdata, flags, rc, properties=None):
    if rc == 0:
        print(f"Connected successfully to MQTT Broker: {MQTT_BROKER}:{MQTT_PORT}")
    else:
        print(f"Failed to connect to MQTT Broker. Return code: {rc}")

def on_publish(client, userdata, mid, reason_code, properties):
    print(f"Encrypted message published successfully with mid: {mid}, Reason Code: {reason_code}")

def on_disconnect(client, userdata, rc, properties=None):
    print(f"Disconnected from MQTT Broker. Return code: {rc}")

# Rest of your weather fetching code remains the same...
def fetch_weather_data():
    """Fetch weather data from MET Malaysia API"""
    try:
        now = datetime.now().strftime('%Y-%m-%d')
        
        url = f"{API_BASE_URL}?datasetid=FORECAST&datacategoryid=GENERAL&locationid=LOCATION:300&start_date={now}&end_date={now}"
        
        headers = {
            'Authorization': f'METToken {API_TOKEN}',
            'Content-Type': 'application/json'
        }
        
        print(f"Fetching weather data for {now}...")
        response = requests.get(url, headers=headers, verify=False)
        
        if response.status_code == 200:
            data = response.json()
            return parse_weather_data(data)
        else:
            print(f"API request failed with status code: {response.status_code}")
            return None
            
    except Exception as e:
        print(f"Error fetching weather data: {str(e)}")
        return None

def parse_weather_data(data):
    """Parse weather data from API response"""
    try:
        if 'results' not in data:
            print("No results found in API response")
            return None
            
        results = data['results']
        
        # Initialize variables
        tempmin = tempmax = locationname = None
        when = code = None
        codem = coden = codea = None
        
        print(f"Processing {len(results)} weather data points...")
        
        for item in results:
            datatype = item.get('datatype')
            value = item.get('value')
            locationname = item.get('locationname')
            
            if datatype == "FMINT":
                tempmin = value
            elif datatype == "FMAXT":
                tempmax = value
            elif datatype == "FSIGW":
                when = item.get('attributes', {}).get('when')
                code = item.get('attributes', {}).get('code')
            elif datatype == "FGM":
                codem = value
            elif datatype == "FGN":
                coden = value
            elif datatype == "FGA":
                codea = value
        
        # Map weather codes
        if code in WEATHER_CODE_MAP:
            code = WEATHER_CODE_MAP[code]
        
        # Create weather summary
        weather_info = {
            'location': locationname,
            'temp_min': tempmin,
            'temp_max': tempmax,
            'significant_weather': code,
            'morning': codem,
            'noon': coden,
            'afternoon': codea
        }
        
        return weather_info
        
    except Exception as e:
        print(f"Error parsing weather data: {str(e)}")
        return None

def format_weather_message(weather_info):
    """Format weather information into a readable message"""
    if not weather_info:
        return "Weather data unavailable"
    
    # Determine greeting based on current time
    current_hour = datetime.now().hour
    if current_hour < 12:
        greeting = "Good Morning!"
    elif current_hour < 18:
        greeting = "Good Afternoon!"
    else:
        greeting = "Good Evening!"
    
    # Format the message
    message_parts = [greeting]
    
    if weather_info['location']:
        message_parts.append(f"Weather for {weather_info['location']} today:")
    
    if weather_info['temp_min'] and weather_info['temp_max']:
        message_parts.append(f"Min Temp: {weather_info['temp_min']}°C, Max Temp: {weather_info['temp_max']}°C.")
    
    if weather_info['significant_weather']:
        message_parts.append(f"Significant weather: {weather_info['significant_weather']}.")
    
    # Add period-specific weather
    period_weather = []
    if weather_info['morning']:
        period_weather.append(f"Morning: {weather_info['morning']}")
    if weather_info['noon']:
        period_weather.append(f"Noon: {weather_info['noon']}")
    if weather_info['afternoon']:
        period_weather.append(f"Afternoon: {weather_info['afternoon']}")
    
    if period_weather:
        message_parts.append(". ".join(period_weather) + ".")
    
    return " ".join(message_parts)

if __name__ == "__main__":
    print(f"Using Node ID: !{NODE_ID:08x}")
    mqtt_topic = f"{root_topic}{channel}/!{NODE_ID:08x}"
    print(f"Publishing to topic: {mqtt_topic}")
    print(f"Channel: {channel}")
    
    # Fetch weather data
    weather_info = fetch_weather_data()
    if weather_info:
        weather_string = format_weather_message(weather_info)
        
        print("\n--- Formatted Weather String ---")
        print(weather_string)
        print("--------------------------------\n")
        
        # Setup MQTT client
        print(f"Attempting to connect to MQTT Broker: {MQTT_BROKER}:{MQTT_PORT} with user '{MQTT_USERNAME}'")
        
        client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
        client.username_pw_set(username=MQTT_USERNAME, password=MQTT_PASSWORD)
        client.on_connect = on_connect
        client.on_publish = on_publish
        client.on_disconnect = on_disconnect
        
        try:
            client.connect(MQTT_BROKER, MQTT_PORT, 60)
            client.loop_start()
            
            # Wait a moment for connection
            time.sleep(2)
            
            # Publish the weather message
            publish_mqtt_message(weather_string)
            
            # Wait for message to be sent
            time.sleep(2)
            
            client.loop_stop()
            client.disconnect()
            
        except Exception as e:
            print(f"MQTT connection error: {str(e)}")
    else:
        print("Failed to fetch weather data")
      
