
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
from sklearn.metrics import confusion_matrix
import seaborn as sns
import matplotlib.pyplot as plt
import seaborn as sns
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
from sklearn.cluster import KMeans
import gc
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.neighbors import KNeighborsClassifier
from sklearn.naive_bayes import GaussianNB


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def safe_read_csv(file_path):
    try:
        return pd.read_csv(file_path)
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

def fetch_src_dataset(medbot_folder_malicious='/home/cpitumpeappu/wireless/CSV_DATASETS/MedBotIoT_Dataset/CSV_FILES/Mirai',
                     medbot_folder_benign='/home/cpitumpeappu/wireless/CSV_DATASETS/MedBotIoT_Dataset/CSV_FILES/Benign'):


    logger.info("Fetching source dataset...")

    medbot_mirai_dataframe = fetch_dataset(medbot_folder_malicious)
    medbot_benign_dataframe = fetch_dataset(medbot_folder_benign)

    if medbot_mirai_dataframe.empty or medbot_benign_dataframe.empty:
        logger.error("One or both datasets are empty")
        return pd.DataFrame()

    medbot_mirai_dataframe['Label'] = 1
    medbot_benign_dataframe['Label'] = 0
    overall_medbot = pd.concat([medbot_benign_dataframe, medbot_mirai_dataframe])

    return overall_medbot

models = [
    ('KNN', KNeighborsClassifier(n_neighbors=7,weights='uniform')),
    # ('SVM', SVC(gamma="scale",random_state=42)),
    ('Naive Bayes', GaussianNB()),
    ('Logistic Regression', LogisticRegression(max_iter=1000,random_state=42)),
    ('Decision Tree', DecisionTreeClassifier(random_state=42)),
    ('Random Forest', RandomForestClassifier(n_estimators=200,max_depth=None,min_samples_split=5,random_state=42)),
    ('Gradient Boosting', GradientBoostingClassifier(n_estimators=200,learning_rate = 0.1,max_depth=7,min_samples_split=7,random_state=42)),
    ('K-Means', KMeans(n_clusters=2,random_state=42))
]

def perform_cross_validation(models, X, y, cv=5):
    results = []
    metrics = ['accuracy', 'precision_weighted', 'recall_weighted', 'f1_weighted']

    for name, model in models:
        print(f"Performing cross-validation for {name}")

        cv_results = cross_validate(
            model, X, y,
            cv=cv,
            scoring=metrics,
            return_train_score=True,
            n_jobs=-1
        )

        for metric in metrics:
            test_metric = f'test_{metric}'
            train_metric = f'train_{metric}'

            results.append({
                'Model': name,
                'Metric': metric.replace('_weighted', '').capitalize(),
                'Train Score': cv_results[train_metric].mean(),
                'Train Std': cv_results[train_metric].std(),
                'Test Score': cv_results[test_metric].mean(),
                'Test Std': cv_results[test_metric].std()
            })

    return pd.DataFrame(results)


def plot_cv_results(cv_results_df):
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
    plt.savefig('cross_validation_results_ddos.png')
    plt.show()

accuracy_results = {}
classification_report_results = {}
confusion_matrix_results = {}
saved_models = {}

def compare_models(models, X_train, X_test, y_train, y_test, dataset_name):
    results = []
    for name, model in models:
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
        if name not in confusion_matrix_results.keys():
          confusion_matrix_results[name] = cm.tolist()

        plt.figure(figsize=(8, 6))
        sns.heatmap(cm, annot=True, fmt='d', cmap='Blues')
        plt.title(f'Confusion Matrix - {name}')
        plt.ylabel('True Label')
        plt.xlabel('Predicted Label')
        plt.show()

    with open(f"./{dataset_name}_confusion_matrices_ddos_source.json", 'w') as f:
      json.dump(confusion_matrix_results, f, indent=4)
      f.close()


    return pd.DataFrame(results)

def evaluate_models_on_target(saved_models, X_test_target, y_test_target, dataset_name):
    confusion_matrix_results_target = {}
    results = []

    for name, model_path in saved_models.items():
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


    with open(f"./{dataset_name}_confusion_matrices_target_ddos.json", 'w') as f:
      json.dump(confusion_matrix_results_target, f, indent=4)
      f.close()

    return pd.DataFrame(results)

import re
import os
from collections import defaultdict
import random

def sample_dos_files(file_list, samples_per_type=3):
    attack_groups = defaultdict(list)

    for file_path in file_list:
        filename = file_path.name
        attack_type = ''.join([c for c in filename.split('.')[0] if not c.isdigit()])
        attack_groups[attack_type].append(file_path)

    sampled_files = {}
    for attack_type, files in attack_groups.items():
        n_samples = min(samples_per_type, len(files))
        sampled_files[attack_type] = random.sample(files, n_samples)

    return sampled_files

def fetch_dataset_sampled(path_to_dataset,flag_sample=False):
    result = pd.DataFrame()
    path = Path(path_to_dataset)

    if not path.exists():
        logger.error(f"Path does not exist: {path_to_dataset}")
        return result

    all_paths = list(path.rglob("*.csv"))

    if flag_sample:
        random.seed(42)
        sampled_files_dict = sample_dos_files(all_paths, samples_per_type=2)
        files_to_process = [file for files in sampled_files_dict.values() for file in files]
    else:
        files_to_process = all_paths

    for csv_file in files_to_process:
        print(f"Processing: {csv_file}")

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


def fetch_src_dataset(folder_malicious='/home/cpitumpeappu/wireless/CSV_DATASETS/CIC_IOT_Dataset2023/CSV_FILES/DDOS',
                     folder_benign='/home/cpitumpeappu/wireless/CSV_DATASETS/CIC_IOT_Dataset2023/CSV_FILES/Benign'):


    print("Fetching source dataset...")

    dos_dataframe = fetch_dataset_sampled(folder_malicious,True)
    benign_dataframe = fetch_dataset_sampled(folder_benign)
    dos_dataframe = dos_dataframe.sample(n=int(benign_dataframe.shape[0]), random_state=42)


    print("DoS DataFrame size:", dos_dataframe.shape)
    print("Benign DataFrame size:", benign_dataframe.shape)


    if dos_dataframe.empty or benign_dataframe.empty:
        logger.error("One or both datasets are empty")
        return pd.DataFrame()

    dos_dataframe['Label'] = 1
    benign_dataframe['Label'] = 0
    overall = pd.concat([benign_dataframe, dos_dataframe])

    del dos_dataframe
    del benign_dataframe
    gc.collect()


    overall = overall.sample(frac=1, random_state=42).reset_index(drop=True)

    return overall

source_ciciot_ddos_dataset = fetch_src_dataset()

y = source_ciciot_ddos_dataset["Label"]
X = source_ciciot_ddos_dataset.drop(['Label'], axis=1)

del source_ciciot_ddos_dataset
gc.collect()

X.replace([np.inf, -np.inf], np.nan, inplace=True)
X.fillna(0, inplace=True)

cv_results_df = perform_cross_validation(models, X, y, cv=5)
cv_results_df.to_csv('./cross_validation_results_ddos.csv', index=False)

print("Plotting cross-validation results...")
plot_cv_results(cv_results_df)

print("\nDetailed Cross-validation Results:")
for model in cv_results_df['Model'].unique():
    print(f"\n{model}:")
    model_results = cv_results_df[cv_results_df['Model'] == model]
    for _, row in model_results.iterrows():
        print(f"{row['Metric']}:")
        print(f"  Train: {row['Train Score']:.3f} (±{row['Train Std']:.3f})")
        print(f"  Test:  {row['Test Score']:.3f} (±{row['Test Std']:.3f})")

X_train_source, X_test_source, y_train_source, y_test_source = train_test_split(X, y, test_size=0.2, random_state=42)
results_df = compare_models(models, X_train_source, X_test_source, y_train_source, y_test_source, "DDOS_CICIOT")
print(results_df)
results_df.to_csv('./model_performance_on_source_ddos.csv')

del X_train_source
del X_test_source
del y_train_source
del y_test_source
gc.collect()

def fetch_mqt(folder_malicious='/home/cpitumpeappu/wireless/CSV_DATASETS/DoS-DDoS-MQTT-IoT_Dataset/CSV_FILES/DDOS',
                     folder_benign='/home/cpitumpeappu/wireless/CSV_DATASETS/DoS-DDoS-MQTT-IoT_Dataset/CSV_FILES/Benign'):

    dos_dataframe = fetch_dataset_sampled(folder_malicious)
    benign_dataframe = fetch_dataset_sampled(folder_benign)

    dos_dataframe = dos_dataframe.sample(n=50000, random_state=42)
    benign_dataframe = benign_dataframe.sample(n=50000, random_state=42)

    print("DoS DataFrame size:", dos_dataframe.shape)
    print("Benign DataFrame size:", benign_dataframe.shape)


    if dos_dataframe.empty or benign_dataframe.empty:
        logger.error("One or both datasets are empty")
        return pd.DataFrame()

    dos_dataframe['Label'] = 1
    benign_dataframe['Label'] = 0
    overall_medbot = pd.concat([benign_dataframe, dos_dataframe])

    del dos_dataframe
    del benign_dataframe
    gc.collect()


    overall_medbot = overall_medbot.sample(frac=1, random_state=42).reset_index(drop=True)

    return overall_medbot



mqtt = fetch_mqt()

y = mqtt["Label"]
X = mqtt.drop(['Label'], axis=1)
X = X.replace([np.inf, -np.inf], np.nan)
X = X.fillna(0)
X_train_target, X_test_target, y_train_target, y_test_target = train_test_split(X, y, test_size=0.2, random_state=42)

target_results = evaluate_models_on_target(saved_models, X_test_target, y_test_target,"MQTT")
print(target_results)
target_results.to_csv('./model_performance_on_target_MQTT_DDOS.csv')
