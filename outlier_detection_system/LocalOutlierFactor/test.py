from os import listdir
from os.path import isfile, join
from progress.bar import Bar
from scapy.all import rdpcap,IP,TCP,UDP
import pandas as pd
from sklearn.preprocessing import LabelEncoder
import numpy as np
from sklearn.ensemble import IsolationForest
import argparse,os
import pickle
from sklearn.feature_selection import SelectFromModel


def main():
  # Read all the csv files
  csvPath = "./test_csv"
  csvFiles = [f for f in listdir(csvPath) if isfile(join(csvPath, f))]
  dfT = pd.read_csv('./processed_csv/processed.csv',index_col=False)
  dfT = dfT.drop(columns=['label'],axis=0)
  print(dfT.columns)
  
  dfs = [] 
  for cv in csvFiles:
    print("CSV Processing: "+cv)
    dfs.append(pd.read_csv(csvPath+'/'+cv,index_col=False))
  
  df = pd.concat(dfs, ignore_index=True)
  #df = df.drop('Unnamed: 0', axis=1)

  # Process all the csv file
  totalNormal = 0
  totalAnomalies =0 
 
  # Turn every column to numeric
  cols = [c for c in df.columns]

  nom_cols = ['ip_flags','tcp_udp_flags','payload']    
  for c in nom_cols:
    le = LabelEncoder()
    df[c] = le.fit_transform(df[c])
  

  # Same calls with the train
  df = df[dfT.columns]

  # Use the isolation forest to find the anomalies -1: anomaly 1:normal 
  filename = 'model.sav'
  clf = pickle.load(open(filename,'rb'))
  df['label']=clf.predict(df) 

  totalNormal = len(df[df['label']==1])
  totalAnomalies = len(df[df['label']==-1])
  print("Normal: "+str(totalNormal))
  print("Anomaly: "+str(totalAnomalies))
  print('Accuracy: '+str(totalAnomalies/float(totalNormal+totalAnomalies)))
  df.to_csv('./test_processed/'+'processed.csv',index=False)

  #Save the model
  filename = 'model.sav'
  pickle.dump(clf,open(filename,'wb'))

if __name__ == "__main__":
  main()

