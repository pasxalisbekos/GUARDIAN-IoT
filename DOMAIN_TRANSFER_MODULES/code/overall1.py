import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score
from sklearn.metrics import confusion_matrix
import seaborn as sns
import matplotlib.pyplot as plt
import seaborn as sns
import os
import matplotlib.gridspec as gridspec
import json
import logging
from pathlib import Path
import numpy as np
from sklearn.model_selection import cross_validate
import matplotlib.pyplot as plt
import seaborn as sns
import joblib
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, confusion_matrix
from sklearn.metrics import precision_score, recall_score, f1_score
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.cluster import KMeans
import gc
import os
import random
from collections import defaultdict
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.neighbors import KNeighborsClassifier
from sklearn.naive_bayes import GaussianNB

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def safe_read_csv(file_path):
    if os.path.getsize(file_path) == 0:
        logger.warning(f"Skipping empty file: {file_path}")
        return None
    try:
        return pd.read_csv(file_path)
    except pd.errors.EmptyDataError:
        logger.error(f"EmptyDataError: No columns to parse from file {file_path}")
        return None
    except Exception as e:
        logger.info(f"Trying alternative engine for {file_path}")
        try:
            return pd.read_csv(file_path, engine='python')
        except Exception as e:
            logger.info(f"Python engine failed, trying with chunks for {file_path}")
            try:
                return pd.concat(chunk for chunk in pd.read_csv(file_path, chunksize=10000))
            except Exception as e:
                logger.error(f"Failed to read {file_path}: {str(e)}")
                return None

def fetch_dataset(path_to_dataset):
    result = pd.DataFrame()
    path = Path(path_to_dataset)

    if not path.exists():
        logger.error(f"Path does not exist: {path_to_dataset}")
        return result

    for csv_file in path.rglob("*.csv"):
        logger.info(f"Processing: {csv_file}")

        df = safe_read_csv(csv_file)
        if df is not None:
            try:
                df = df.select_dtypes(include='number')

                cols_to_drop = ['Src Port', 'Dst Port']
                existing_cols = [col for col in cols_to_drop if col in df.columns]
                if existing_cols:
                    df = df.drop(columns=existing_cols)

                result = pd.concat([result, df], ignore_index=True)
                logger.info(f"Successfully processed {csv_file}")
            except Exception as e:
                logger.error(f"Error processing {csv_file}: {str(e)}")

    return result

def get_sample_files(base_dir):
    directory_samples = {}

    for subdir in os.listdir(base_dir):
        subdir_path = os.path.join(base_dir, subdir)
        if not os.path.isdir(subdir_path):
            continue

        file_groups = defaultdict(list)
        for filename in os.listdir(subdir_path):
            base_name = ''.join(c for c in filename if not c.isdigit()).replace('.pcap_Flow', '')
            file_groups[base_name].append(filename)

        samples = {}
        for base_name, files in file_groups.items():
            sample_size = min(1, len(files))
            samples[base_name] = random.sample(files, sample_size)

        directory_samples[subdir] = samples

    return directory_samples


def get_ciciot_dataset():
    base_dir = '/home/cpitumpeappu/wireless/CSV_DATASETS/CIC_IOT_Dataset2023/CSV_FILES'
    folders = os.listdir(base_dir)
    print("Folders in directory:", folders)

    samples = get_sample_files(base_dir)
    per_type_df = {}
    labels = [0, 1, 2, 3]
    # 0 : Benign
    # 1 : Mirai
    # 2 : DDoS
    # 3 : DoS

    overall_pd = pd.DataFrame()
    for directory, file_groups in samples.items():
        print(f"\n{directory}:")
        for base_name, files in file_groups.items():
            label = None
            if directory == "DDOS":
                label = 2
            elif directory == "Mirai":
                label = 1
            elif directory == "Dos":
                label = 3
            elif directory == "Benign":
                label = 0

            for file in files:
                print(f"  {file}")
                file_path = os.path.join(base_dir, directory, file)
                df = safe_read_csv(file_path)  # Use safe_read_csv
                if df is not None and not df.empty:
                    if len(df) > 50000:
                        df = df.sample(n=50000, random_state=42)
                    df['Label'] = label
                    overall_pd = pd.concat([overall_pd, df], ignore_index=True)

    overall_pd = overall_pd.select_dtypes(include='number')
    cols_to_drop = ['Src Port', 'Dst Port']
    overall_pd = overall_pd.drop(columns=cols_to_drop, errors='ignore')  # Use errors='ignore' to avoid dropping missing columns
    overall_pd = overall_pd.sample(frac=1, random_state=42).reset_index(drop=True)
    return overall_pd

ciciot_dataset = get_ciciot_dataset()

from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.cluster import KMeans

models = [
    ('KNN', KNeighborsClassifier(n_neighbors=7, weights='uniform')),
    # ('SVM', SVC(gamma="scale", random_state=42)),
    ('Naive Bayes', GaussianNB()),
    ('Logistic Regression', LogisticRegression(max_iter=1000, random_state=42, multi_class='multinomial')),
    ('Decision Tree', DecisionTreeClassifier(random_state=42)),
    ('Random Forest', RandomForestClassifier(n_estimators=200, max_depth=None, min_samples_split=5, random_state=42)),
    ('Gradient Boosting', GradientBoostingClassifier(n_estimators=200, learning_rate=0.1, max_depth=7, min_samples_split=7, random_state=42)),
    ('K-Means', KMeans(n_clusters=4, random_state=42))
]

def perform_cross_validation(models, X, y, cv=5):
    results = []
    metrics = ['accuracy', 'precision_macro', 'recall_macro', 'f1_macro']

    for name, model in models:
        print(f"Performing cross-validation for {name}")

        if isinstance(model, KMeans):
            cv_results = {
                'test_accuracy': [],
                'train_accuracy': [],
                'test_precision_macro': [],
                'train_precision_macro': [],
                'test_recall_macro': [],
                'train_recall_macro': [],
                'test_f1_macro': [],
                'train_f1_macro': []
            }

            from sklearn.model_selection import KFold
            kf = KFold(n_splits=cv, shuffle=True, random_state=42)

            for train_idx, test_idx in kf.split(X):
                X_train, X_test = X.iloc[train_idx], X.iloc[test_idx]
                y_train, y_test = y.iloc[train_idx], y.iloc[test_idx]

                model.fit(X_train)
                train_pred = model.predict(X_train)
                test_pred = model.predict(X_test)

                cv_results['train_accuracy'].append(accuracy_score(y_train, train_pred))
                cv_results['test_accuracy'].append(accuracy_score(y_test, test_pred))
                cv_results['train_precision_macro'].append(precision_score(y_train, train_pred, average='macro'))
                cv_results['test_precision_macro'].append(precision_score(y_test, test_pred, average='macro'))
                cv_results['train_recall_macro'].append(recall_score(y_train, train_pred, average='macro'))
                cv_results['test_recall_macro'].append(recall_score(y_test, test_pred, average='macro'))
                cv_results['train_f1_macro'].append(f1_score(y_train, train_pred, average='macro'))
                cv_results['test_f1_macro'].append(f1_score(y_test, test_pred, average='macro'))

            for key in cv_results:
                cv_results[key] = np.array(cv_results[key])
        else:
            cv_results = cross_validate(
                model, X, y,
                cv=cv,
                scoring={
                    'accuracy': 'accuracy',
                    'precision_macro': 'precision_macro',
                    'recall_macro': 'recall_macro',
                    'f1_macro': 'f1_macro'
                },
                return_train_score=True,
                n_jobs=-1
            )

        for metric in metrics:
            test_metric = f'test_{metric}'
            train_metric = f'train_{metric}'

            results.append({
                'Model': name,
                'Metric': metric.replace('_macro', '').capitalize(),
                'Train Score': cv_results[train_metric].mean(),
                'Train Std': cv_results[train_metric].std(),
                'Test Score': cv_results[test_metric].mean(),
                'Test Std': cv_results[test_metric].std()
            })

    return pd.DataFrame(results)

def plot_cv_results(cv_results_df, output_filename='cross_validation_results_all_attacks.png'):
    plt.figure(figsize=(15, 10))

    models = cv_results_df['Model'].unique()
    metrics = cv_results_df['Metric'].unique()
    x = np.arange(len(models))
    width = 0.35

    fig, axes = plt.subplots(2, 2, figsize=(20, 15))
    axes = axes.ravel()

    for idx, metric in enumerate(metrics):
        metric_data = cv_results_df[cv_results_df['Metric'] == metric]

        ax = axes[idx]
        train_bars = ax.bar(x - width/2, metric_data['Train Score'], width, label='Train', alpha=0.8)
        test_bars = ax.bar(x + width/2, metric_data['Test Score'], width, label='Test', alpha=0.8)

        ax.errorbar(x - width/2, metric_data['Train Score'], yerr=metric_data['Train Std'], fmt='none', color='black', capsize=5)
        ax.errorbar(x + width/2, metric_data['Test Score'], yerr=metric_data['Test Std'], fmt='none', color='black', capsize=5)

        ax.set_ylabel('Score')
        ax.set_title(f'{metric} Scores')
        ax.set_xticks(x)
        ax.set_xticklabels(models, rotation=45, ha='right')
        ax.legend()
        ax.grid(True, alpha=0.3)

        def add_labels(bars):
            for bar in bars:
                height = bar.get_height()
                ax.text(bar.get_x() + bar.get_width()/2., height,
                       f'{height:.3f}', ha='center', va='bottom')

        add_labels(train_bars)
        add_labels(test_bars)

    plt.tight_layout()
    plt.savefig(output_filename)
    plt.show()

y = ciciot_dataset["Label"]
X = ciciot_dataset.drop(['Label'], axis=1)

del ciciot_dataset
gc.collect()

X.replace([np.inf, -np.inf], np.nan, inplace=True)
X.fillna(0, inplace=True)
results = perform_cross_validation(models, X, y)
plot_cv_results(results, 'cross_validation_results_multiclass_all_attacks.png')
results.to_csv('./cross_validation_results_multiclass_all_attacks_source.csv')

accuracy_results = {}
classification_report_results = {}
confusion_matrix_results = {}
saved_models = {}

def compare_models(models, X_train, X_test, y_train, y_test, dataset_name):
    results = []
    confusion_matrix_results = {}
    class_labels = ['Benign', 'Mirai', 'DDoS', 'DoS']

    n_models = len(models)
    n_cols = 2
    n_rows = (n_models + n_cols - 1) // n_cols

    fig = plt.figure(figsize=(15, 5*n_rows))
    gs = gridspec.GridSpec(n_rows, n_cols)
    gs.update(wspace=0.3, hspace=0.4)

    for idx, (name, model) in enumerate(models):
        print(f"Training with {name}")
        model.fit(X_train, y_train)
        y_pred = model.predict(X_test)
        joblib.dump(model, f"{name}_model.pkl")
        saved_models[name] = f"{name}_model.pkl"

        results.append({
            'Model': name,
            'Accuracy': accuracy_score(y_test, y_pred),
            'Precision': precision_score(y_test, y_pred, average='weighted'),
            'Recall': recall_score(y_test, y_pred, average='weighted'),
            'F1': f1_score(y_test, y_pred, average='weighted')
        })
        cm = confusion_matrix(y_test, y_pred)
        confusion_matrix_results[name] = cm.tolist()

        ax = plt.subplot(gs[idx])
        sns.heatmap(cm, annot=True, fmt='d', cmap='Blues',
                   xticklabels=class_labels,
                   yticklabels=class_labels,
                   ax=ax)
        ax.set_title(f'Confusion Matrix - {name}')
        ax.set_ylabel('True')
        ax.set_xlabel('Predicted')
        ax.set_xticklabels(ax.get_xticklabels(), rotation=45, ha='right')

    plt.tight_layout()
    plt.savefig(f'confusion_matrices_{dataset_name}.png', bbox_inches='tight', dpi=300)
    plt.show()

    with open(f"./{dataset_name}_confusion_matrices_all_attacks_source.json", 'w') as f:
        json.dump(confusion_matrix_results, f, indent=4)

    return pd.DataFrame(results)

X_train_source, X_test_source, y_train_source, y_test_source = train_test_split(X, y, test_size=0.2, random_state=42)

results_df = compare_models(models, X_train_source, X_test_source, y_train_source, y_test_source, "DDOS_CICIOT")
print(results_df)
results_df.to_csv('./accuracy_results_multiclass_all_attacks_source.csv')








def get_mirai_dataset_medbotiot():
  base_dir = '/home/cpitumpeappu/wireless/CSV_DATASETS/MedBotIoT_Dataset/CSV_FILES'
  folders = os.listdir(base_dir)
  print("Folders in directory:", folders)

  samples = get_sample_files(base_dir)
  per_type_df = {}
  labels = [0,1,2,3]
  # 0 : Benign
  # 1 : Mirai
  # 2 : DDoS
  # 3 : DoS

  overall_pd = pd.DataFrame()
  for directory, file_groups in samples.items():
      print(f"\n{directory}:")
      for base_name, files in file_groups.items():
          label = None
          if directory == "DDOS":
              label = 2
          elif directory == "Mirai":
              label = 1
          elif directory == "Dos":
              label = 3
          elif directory == "Benign":
              label = 0

          for file in files:
            print(f"  {file}")
            file_path = os.path.join(base_dir, directory, file)
            df = pd.read_csv(file_path)
            if len(df) > 50000:
              df = df.sample(n=50000, random_state=42)

            df['Label'] = label
            overall_pd = pd.concat([overall_pd, df], ignore_index=True)

  overall_pd = overall_pd.select_dtypes(include='number')
  cols_to_drop = ['Src Port', 'Dst Port']
  overall_pd = overall_pd.drop(columns=cols_to_drop)
  overall_pd = overall_pd.sample(frac=1, random_state=42).reset_index(drop=True)
  return overall_pd

def get_mirai_dataset_iot23():
  base_dir = '/home/cpitumpeappu/wireless/CSV_DATASETS/IoT_23_Dataset/CSV_FILES'
  folders = os.listdir(base_dir)
  print("Folders in directory:", folders)

  samples = get_sample_files(base_dir)
  per_type_df = {}
  labels = [0,1,2,3]
  # 0 : Benign
  # 1 : Mirai
  # 2 : DDoS
  # 3 : DoS

  overall_pd = pd.DataFrame()
  for directory, file_groups in samples.items():
      print(f"\n{directory}:")
      for base_name, files in file_groups.items():
          label = None
          if directory == "DDOS":
              label = 2
          elif directory == "Mirai":
              label = 1
          elif directory == "Dos":
              label = 3
          elif directory == "Benign":
              label = 0

          for file in files:
            print(f"  {file}")
            file_path = os.path.join(base_dir, directory, file)
            df = pd.read_csv(file_path)
            if len(df) > 50000:
              df = df.sample(n=50000, random_state=42)

            df['Label'] = label
            overall_pd = pd.concat([overall_pd, df], ignore_index=True)

  overall_pd = overall_pd.select_dtypes(include='number')
  cols_to_drop = ['Src Port', 'Dst Port']
  overall_pd = overall_pd.drop(columns=cols_to_drop)
  overall_pd = overall_pd.sample(frac=1, random_state=42).reset_index(drop=True)
  return overall_pd


def get_iot_netintr_dos_mirai():

  iot_network_intrusion_df = pd.read_csv('./IoT-Network Intrusion/IoT Network Intrusion Dataset.csv')
  iot_network_intrusion_df.columns = iot_network_intrusion_df.columns.str.replace('_', ' ')

  iot_network_intrusion_dos = iot_network_intrusion_df[iot_network_intrusion_df['Cat'] == 'DoS']
  iot_network_intrusion_dos = iot_network_intrusion_dos.select_dtypes(include='number')
  iot_network_intrusion_dos = iot_network_intrusion_dos.drop(columns=['Src Port','Dst Port'])
  iot_network_intrusion_dos['Label'] = 3

  iot_network_intrusion_mirai = iot_network_intrusion_df[iot_network_intrusion_df['Cat'] == 'Mirai']
  iot_network_intrusion_mirai = iot_network_intrusion_mirai.select_dtypes(include='number')
  iot_network_intrusion_mirai = iot_network_intrusion_mirai.drop(columns=['Src Port','Dst Port'])
  iot_network_intrusion_mirai['Label'] = 1

  iot_network_intrusion_normal = iot_network_intrusion_df[iot_network_intrusion_df['Cat'] == 'Normal']
  iot_network_intrusion_normal = iot_network_intrusion_normal.select_dtypes(include='number')
  iot_network_intrusion_normal = iot_network_intrusion_normal.drop(columns=['Src Port','Dst Port'])
  iot_network_intrusion_normal['Label'] = 0

  # print("DoS DataFrame size:", iot_network_intrusion_dos.shape)
  # print("Benign DataFrame size:", iot_network_intrusion_normal.shape)
  if (len(iot_network_intrusion_mirai) > 50000):
      iot_network_intrusion_mirai = iot_network_intrusion_mirai.sample(n=50000, random_state=42)
  if (len(iot_network_intrusion_dos) > 50000):
      iot_network_intrusion_dos = iot_network_intrusion_dos.sample(n=50000, random_state=42)
  if (len(iot_network_intrusion_normal) > 50000):
      iot_network_intrusion_normal = iot_network_intrusion_normal.sample(n=50000, random_state=42)


  attack_w_benign = pd.concat([iot_network_intrusion_dos,iot_network_intrusion_normal,iot_network_intrusion_mirai])
  attack_w_benign = attack_w_benign.sample(frac=1, random_state=42).reset_index(drop=True)

  return attack_w_benign



def get_mqt_dataset_ddos_dos():
  base_dir = 'DoS-DDoS-MQTT-IoT_Dataset/CSV_FILES'
  folders = os.listdir(base_dir)
  print("Folders in directory:", folders)

  samples = get_sample_files(base_dir)
  per_type_df = {}
  labels = [0,1,2,3]
  # 0 : Benign
  # 1 : Mirai
  # 2 : DDoS
  # 3 : DoS

  overall_pd = pd.DataFrame()
  for directory, file_groups in samples.items():
      print(f"\n{directory}:")
      for base_name, files in file_groups.items():
          label = None
          if directory == "DDOS":
              label = 2
          elif directory == "Mirai":
              label = 1
          elif directory == "Dos":
              label = 3
          elif directory == "Benign":
              label = 0

          for file in files:
            print(f"  {file}")
            file_path = os.path.join(base_dir, directory, file)
            df = pd.read_csv(file_path)
            if len(df) > 50000:
              df = df.sample(n=50000, random_state=42)

            df['Label'] = label
            overall_pd = pd.concat([overall_pd, df], ignore_index=True)

  overall_pd = overall_pd.select_dtypes(include='number')
  cols_to_drop = ['Src Port', 'Dst Port']
  overall_pd = overall_pd.drop(columns=cols_to_drop)
  overall_pd = overall_pd.sample(frac=1, random_state=42).reset_index(drop=True)
  return overall_pd
  pass

med_bot_mirai_dataset = get_mirai_dataset_medbotiot()
iot_net_intr_dataset = get_iot_netintr_dos_mirai()
iot_23_dataset = get_mirai_dataset_iot23()
mqt_dataset = get_mqt_dataset_ddos_dos()

def evaluate_models_on_target(saved_models, X_test_target, y_test_target, dataset_name):
    confusion_matrix_results_target = {}
    results = []
    class_labels = ['Benign', 'Mirai', 'DDoS', 'DoS']
    n_models = len(saved_models)
    n_cols = 2
    n_rows = (n_models + n_cols - 1) // n_cols

    fig = plt.figure(figsize=(15, 5*n_rows))
    gs = gridspec.GridSpec(n_rows, n_cols)
    gs.update(wspace=0.3, hspace=0.4)

    for idx, (name, model_path) in enumerate(saved_models.items()):
        model = joblib.load(model_path)
        y_pred = model.predict(X_test_target)

        results.append({
            'Model': name,
            'Accuracy': accuracy_score(y_test_target, y_pred),
            'Precision': precision_score(y_test_target, y_pred, average='weighted'),
            'Recall': recall_score(y_test_target, y_pred, average='weighted'),
            'F1': f1_score(y_test_target, y_pred, average='weighted')
        })

        cm = confusion_matrix(y_test_target, y_pred)
        confusion_matrix_results_target[name] = cm.tolist()

        ax = plt.subplot(gs[idx])
        sns.heatmap(cm, annot=True, fmt='d', cmap='Blues',
                   xticklabels=class_labels,
                   yticklabels=class_labels,
                   ax=ax)
        ax.set_title(f'Confusion Matrix for {name}')
        ax.set_ylabel('True')
        ax.set_xlabel('Predicted')
        ax.set_xticklabels(ax.get_xticklabels(), rotation=45, ha='right')

    plt.tight_layout()
    plt.savefig(f'confusion_matrices_target_{dataset_name}_all_attacks.png', bbox_inches='tight', dpi=300)
    plt.show()

    with open(f"./{dataset_name}_confusion_matrices_target_all.json", 'w') as f:
        json.dump(confusion_matrix_results_target, f, indent=4)

    return pd.DataFrame(results)

# print(iot_net_intr_dataset.head(10))
overall_dataset = pd.concat([med_bot_mirai_dataset,iot_net_intr_dataset,iot_23_dataset,mqt_dataset])
y = overall_dataset["Label"]
X = overall_dataset.drop(['Label'], axis=1)

X = X.replace([np.inf, -np.inf], np.nan)
X = X.fillna(0)
X_train_target, X_test_target, y_train_target, y_test_target = train_test_split(X, y, test_size=0.2, random_state=42)
target_results = evaluate_models_on_target(saved_models, X_test_target, y_test_target,"combined_datasets_all_attacks")
print("\nModels Performance on All targets and Attacks:")
print(target_results)
target_results.to_csv('./model_performance_on_target_all_attacks.csv')

label_counts = overall_dataset['Label'].value_counts()
print("\nLabel distribution:")
for label, count in label_counts.items():
    label_name = {
        0: 'Benign',
        1: 'Mirai',
        2: 'DDoS',
        3: 'DoS'
    }[label]
    print(f"{label_name} (label {label}): {count:,} samples")



print("\nPercentage distribution:")
percentages = overall_dataset['Label'].value_counts(normalize=True) * 100
for label, percentage in percentages.items():
    label_name = {
        0: 'Benign',
        1: 'Mirai',
        2: 'DDoS',
        3: 'DoS'
    }[label]
    print(f"{label_name} (label {label}): {percentage:.2f}%")
