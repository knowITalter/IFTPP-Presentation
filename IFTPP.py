"""
Name: Jonathan Alter

Partners:
    > Spencer Yost
    > Jan Masztal
    > Matthew Thibodeaux
"""
import hashlib
import base64
import json

# Client random bytes (as hexstring)
c = bytes.fromhex('4f163f5f0f9a621d729566c74d10037c')
# Server random bytes (as hexstring)
s = bytes.fromhex('52fdfc072182654f163f5f0f9a621d72')
# Shared key - calculated in golang
shared_key = "68597258426b324350694649544a3374394e435675584e6f6a4c6f3d"

def gen_checksum(hex_data):
    """
    Takes the payload of the IFTPP packet and calculates the checksum.
    
    hex_data: A hexstring representing the IFTPP payload
    """
    data = bytes.fromhex(hex_data)
    sha1 = hashlib.sha1(data).digest()
    b64 = base64.b64encode(sha1)
    return b64[-9:-1].hex()
    

def read_iftpp_data(hex_data):
    """
    Takes a hexstring representing ICMP payload (`hex_data`) and interprets it as a IFTPP packet. 
    NOTE: This assumes the packet contains a Flag!!!
    
    Parameters:
        hex_data:   a hexstring representing the ICMP data payload
    Returns:
        dict: A dictionary representation of the IFTPP packet.
    """
    data = bytes.fromhex(hex_data)
    flags = data[-2:]
    checksum = data[-10:-2]
    sid = data[-12:-10]
    # seems data packets have an extra byte and start at 5 not 4
    payload = data[5:-12] if flags[-1:].hex() == '05' else data[4:-12]
    calc_cksm = gen_checksum(payload.hex())
    return_val = {"payload": payload.hex(),"flags":flags[-1:].hex(),"sid":sid.hex(),"checksum": checksum.hex(), "calc_cksm": calc_cksm, "checksum_matches": calc_cksm == checksum.hex()}
    return return_val


def xor_chunk(chunk, key):
    """
    XORs the data supplied in `chunk` with the `key`
    Parameters:
        chunk: hexstring representing the key
        key: hexstring representing the key
    Returns:
        bytes: resulting values from an XOR of `chunk` and `key`
    """
    # Convert to bytestrings
    k = bytes.fromhex(key)
    d = bytes.fromhex(chunk)
    #preform xor and return
    return bytes([d[i] ^ k[i % len(k)] for i in range(len(d))])

if __name__ == "__main__":

    # Open wireshark packet dissection for the selected ICMP packets
    with open('packet_dissections.json','r') as f:
        # load it as a json file
        packets = json.load(f)
    
    # Extract the ICMP data field
    icmp_data = []
    for p in packets:
        # Convert to hexstring by removing ':' delimiter
        icmp_data.append(p['_source']['layers']['icmp']['data']['data.data'].replace(":",""))
        
    # Open output JPEG
    with open("out.jpg",'wb') as f:
        # Iterate over the icmp data hexstrings
        for p in icmp_data:
            # Interpret each as a IFTPP packet
            interpreted_packet = read_iftpp_data(p)
            # Check if the flag is set to 'FILE_DATA' ('05')
            if interpreted_packet['flags'] == '05':
                # If yes, XOR payload with key and write the binary data to out.jpg
                f.write(xor_chunk(interpreted_packet['payload'], shared_key))

    