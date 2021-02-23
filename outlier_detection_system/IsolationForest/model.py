from sklearn.model_selection import train_test_split
from os import listdir
from os.path import isfile, join
from progress.bar import Bar
from scapy.all import rdpcap,IP,TCP,UDP
import pandas as pd
import numpy as np
import datetime
from sklearn.metrics import classification_report
from sklearn.metrics import confusion_matrix
from sklearn.metrics import roc_auc_score
from sklearn.ensemble import RandomForestClassifier

def main():
  
  # Read all the csv files
  csvPath = "./processed_csv"
  csvFiles = [f for f in listdir(csvPath) if isfile(join(csvPath, f))]
  
  # Join all the csv
  dfs = [] 
  for cv in csvFiles:
    print("CSV Processing: "+cv)
    dfs.append(pd.read_csv(csvPath+'/'+cv,index_col=False))
  
  df = pd.concat(dfs, ignore_index=True)
  df = df.drop('Unnamed: 0', axis=1)
  
  # Train test split
  X = df.drop('label',axis=1)
  y = df['label']
  X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.30, random_state=42)

  # Create the model and start training
  start = datetime.datetime.now()
  clf = RandomForestClassifier(max_depth=10, random_state=0)
  clf.fit(X, y)
  end = datetime.datetime.now()  
  
  print("Training Time: "+str(end-start))

  y_pred_train = clf.predict(X_train)
 
  print("Training sample :")
  print(y_pred_train)
  print(classification_report(y_train, y_pred_train, target_names=['anomaly', 'normal']))
  print ("AUC: ", "{:.1%}".format(roc_auc_score(y_train, y_pred_train)))
  cm = confusion_matrix(y_train, y_pred_train)
  print(cm)
  #plot_confusion_matrix(cm, title="IF Confusion Matrix - SA")
 

  y_pred_test = clf.predict(X_test)
  print("Testing sample :")
  print(y_pred_test)
  print(classification_report(y_test, y_pred_test, target_names=['anomaly', 'normal']))
  print ("AUC: ", "{:.1%}".format(roc_auc_score(y_test, y_pred_test)))
  cm = confusion_matrix(y_test, y_pred_test)
  print(cm)
  #plot_confusion_matrix(cm, title="IF Confusion Matrix - SA")
   
if __name__ == "__main__":
  main() 
