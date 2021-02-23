from os import listdir
from os.path import isfile, join
from progress.bar import Bar
from scapy.all import rdpcap,IP,TCP,UDP
import pandas as pd
from progress.bar import Bar
from ExtraFeatures import *
import argparse,os
import binascii
import numpy as np
import requests 
import requests
import json

def main():
  
  # Fetch all the topics in order to check the type
  URL = "http://localhost/topics"
  with open('../env.json', 'r') as myfile:
    d=myfile.read()
  headers = json.loads(d)
  r = requests.get(url = URL ,headers=headers)
  topics = r.json()
 
  if(r.status_code != 200):
    print(topics['message'])
    os._exit(-1)
  print(topics)

  # Read all the pcap files
  parser = argparse.ArgumentParser(description='Packet sniffer')
  parser.add_argument('--type',type=str,help='Type of use')
  args = parser.parse_args()

  if not args.type:
    print('--type required')
    os._exit(-1)

  if(args.type == 'train'):
    pcapPath = "./pcap_files"
    pcapFiles = [f for f in listdir(pcapPath) if isfile(join(pcapPath, f))]
  else:
    pcapPath = "./pcap_test"
    pcapFiles = [f for f in listdir(pcapPath) if isfile(join(pcapPath, f))]
  for p in pcapFiles:

    # Read the current pcap
    pcap = rdpcap(pcapPath+"/"+p)

    print('File processed: '+p)

    # Collect field names from IP/TCP/UDP
    ip_fields = [field.name for field in IP().fields_desc]
    tcp_fields = [field.name for field in TCP().fields_desc]
    udp_fields = [field.name for field in UDP().fields_desc]
    dataframe_fields = ip_fields + ['time'] + tcp_fields
    dataframe_fields = dataframe_fields + ['land'] + ['time_diff'] + ['payload']+['std_dev_payload']
    dataframe_fields = dataframe_fields + ["Avg_syn_flag", "Avg_urg_flag", "Avg_fin_flag", "Avg_ack_flag", "Avg_psh_flag", "Avg_rst_flag", "Avg_DNS_pkt", \
      "Avg_TCP_pkt","Avg_UDP_pkt", "Avg_ICMP_pkt", "Duration_window_flow", "Avg_delta_time", "Min_delta_time", "Max_delta_time", "StDev_delta_time",
      "Avg_pkts_lenght", "Min_pkts_lenght", "Max_pkts_lenght", "StDev_pkts_lenght", "Avg_small_payload_pkt", "Avg_payload", "Min_payload",
      "Max_payload", "StDev_payload", "Avg_DNS_over_TCP"] 

    dataframe_fields_after = ip_fields + ['time'] + tcp_fields + ['land']+['time_diff']+['payload']+['std_dev_payload']
    dataframe_fields_after[dataframe_fields_after.index('flags')] = "ip_flags"
    dataframe_fields_after[dataframe_fields_after.index('flags')] = "tcp_udp_flags"
    dataframe_fields_after[dataframe_fields_after.index('chksum')] = "ip_chksum"
    dataframe_fields_after[dataframe_fields_after.index('chksum')] = "tcp_udp_chksum"
    dataframe_fields_after[dataframe_fields_after.index('options')] = "ip_options"
    dataframe_fields_after[dataframe_fields_after.index('options')] = "tcp_udp_options"
    dataframe_fields_after = dataframe_fields_after + ["Avg_syn_flag", "Avg_urg_flag", "Avg_fin_flag", "Avg_ack_flag", "Avg_psh_flag", "Avg_rst_flag", 
      "Avg_DNS_pkt","Avg_TCP_pkt","Avg_UDP_pkt", "Avg_ICMP_pkt", "Duration_window_flow", "Avg_delta_time", "Min_delta_time", "Max_delta_time", 
      "StDev_delta_time","Avg_pkts_lenght", "Min_pkts_lenght", "Max_pkts_lenght", "StDev_pkts_lenght", "Avg_small_payload_pkt", "Avg_payload", "Min_payload",
      "Max_payload", "StDev_payload", "Avg_DNS_over_TCP"]


    # Create the dataframe with the data
    df = pd.DataFrame(columns=dataframe_fields)

    #print(df.head())
    #os._exit(1);
    
    pkts = []
    prevDiff = 0
    for packet in pcap[IP]:
      # Field array for each row of DataFrame
      field_values = []
      # Add all IP fields to dataframe
      for field in ip_fields:
          if field == 'options':
              # Retrieving number of options defined in IP Header
              field_values.append(len(packet[IP].fields[field]))
          else:
              field_values.append(packet[IP].fields[field])
      
      field_values.append(packet.time)
        
      layer_type = type(packet[IP].payload)
      #print(packet[layer_type].payload)
      for field in tcp_fields:
          try:
              if field == 'options':
                  field_values.append(len(packet[layer_type].fields[field]))
              else:
                  field_values.append(packet[layer_type].fields[field])
          except:
              field_values.append(None)

      # land option
      if((packet[IP].fields['src'] == packet[IP].fields['dst']) or (packet[layer_type].fields['sport'] == packet[layer_type].fields['dport'])):
        field_values.append(1)
      else:
        field_values.append(0)
      
      # time diff option
      if len(pkts) > 0:
        field_values.append(field_values[13]-prevDiff)
      else:
        field_values.append(0.0)
      prevDiff = field_values[13]
      pkts.append(packet)

      # Retrieve topic
      topic = (str(bytes(packet[layer_type].payload))[::-1][1::]).split('/')[0]
      topic = "/"+topic[::-1]

      # Retrieve the topic ontology
      ontologyType = ''
      for e in topics:
        if e['name'] == topic:
          ontologyType = e['topic_ontology']
          break

      # Check the payload type and add the payload to the csv
      try:
        payload = str(bytes(packet[layer_type].payload))[::-1][0]
        if ontologyType == 'integer':
          payload = int(payload)
          field_values.append(int(payload))
      except ValueError:
        print('Wrong type of ontology')
        field_values.append(0)

      # standard deviation to the payload
      if len(df['payload']) > 0:
        std_dev_payload = np.std(np.array(df['payload']).astype(int))
        field_values.append(std_dev_payload)
      else:
        field_values.append(0)

      # Append the extra features
      fc = ExtraFeatures()
      extraF = fc.compute_features(pkts)
      
      for it in extraF:
        field_values.append(it)       

      # Take the second packet and so on
      if(len(pkts)>1):
        df_append = pd.DataFrame([field_values], columns=dataframe_fields)
        df = pd.concat([df, df_append], axis=0)
    
    
    # Reset Index
    df.columns = dataframe_fields_after
    df = df.reset_index()

    # Drop old index column
    if(args.type == 'train'):
      df = df.drop(columns=["index","src","dst","id","ip_chksum","seq","ack","tcp_udp_chksum"])
      df.to_csv('./csv_files/'+p+'.csv',index=False)
    else:
      df = df.drop(columns=["index","src","dst","id","ip_chksum","seq","ack","tcp_udp_chksum"])
      df.to_csv('./test_csv/'+p+'.csv',index=False)


if __name__ == '__main__':
  main()
