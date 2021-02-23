from os import listdir
from os.path import isfile, join
from scapy.all import rdpcap,IP,TCP,UDP
import pandas as pd
from sklearn.preprocessing import LabelEncoder
import numpy as np
from sklearn.ensemble import IsolationForest
import argparse,os
import pickle
from sklearn.neighbors import LocalOutlierFactor
from pyod.models.mcd import MCD

def main():
  
  # Read all the csv files
  csvPath = "./csv_files"
  csvFiles = [f for f in listdir(csvPath) if isfile(join(csvPath, f))]
  
  dfs = [] 
  for cv in csvFiles:
    print("CSV Processing: "+cv)
    dfs.append(pd.read_csv(csvPath+'/'+cv,index_col=False))
  
  df = pd.concat(dfs, ignore_index=True)

  # Process all the csv file
  totalNormal = 0
  totalAnomalies =0 
 
  # Turn every column to numeric
  cols = [c for c in df.columns]

  nom_cols = ['ip_flags','tcp_udp_flags','payload']    
  for c in nom_cols:
    le = LabelEncoder()
    df[c] = le.fit_transform(df[c])
  
  # Remove the cols with small standard deviation
  df = df.loc[:, df.std() > 0.0]

  # Calculate the correlation matrix
  corr_matrix = df.corr().abs()

  # Select upper triangle of correlation matrix
  upper = corr_matrix.where(np.triu(np.ones(corr_matrix.shape), k=1).astype(np.bool))

  # Find index of feature columns with correlation greater than 0.95
  to_drop = [column for column in upper.columns if any(upper[column] == 1)]
  
  df = df.drop(df[to_drop],axis=1)

  print(df.head())
    
  # Fit the first model
  clf = MCD().fit(df)

  df['label'] = clf.predict(df)
  print(df) 

  totalNormal = len(df[df['label']==0])
  totalAnomalies = len(df[df['label']==1])
  print("Normal: "+str(totalNormal))
  print("Anomaly: "+str(totalAnomalies))
  print('Accuracy: '+str(totalNormal/float(totalNormal+totalAnomalies)))
  df.to_csv('./processed_csv/'+'processed.csv',index=False)

  #Save the model
  filename = 'model.sav'
  pickle.dump(clf,open(filename,'wb'))

if __name__ == "__main__":
  main()
