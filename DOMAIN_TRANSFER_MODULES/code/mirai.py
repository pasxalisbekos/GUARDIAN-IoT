
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
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
from sklearn.neighbors import KNeighborsClassifier
from sklearn.naive_bayes import GaussianNB
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.cluster import KMeans

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

def fetch_target(path_to_malicious, path_to_benign):
    logger.info(f"Fetching target dataset from {path_to_malicious} and {path_to_benign}")

    mirai_dataframe = fetch_dataset(path_to_malicious)
    benign_dataframe = fetch_dataset(path_to_benign)

    if mirai_dataframe.empty or benign_dataframe.empty:
        logger.error("One or both datasets are empty")
        return pd.DataFrame()

    mirai_dataframe['Label'] = 1
    benign_dataframe['Label'] = 0
    overall = pd.concat([benign_dataframe, mirai_dataframe])

    return overall

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
    plt.savefig('cross_validation_results_mirai.png')
    plt.show()

########################################################################################################################################################################################################################################################
#
#                                                                                                       MIRAI CLASSIFICATION
#
########################################################################################################################################################################################################################################################

try:
    source = fetch_src_dataset()
    overall_iot_23 = fetch_target('/home/cpitumpeappu/wireless/CSV_DATASETS/IoT_23_Dataset/CSV_FILES/Mirai',
                                '/home/cpitumpeappu/wireless/CSV_DATASETS/IoT_23_Dataset/CSV_FILES/Benign')
    overall_ciciot = fetch_target('/home/cpitumpeappu/wireless/CSV_DATASETS/CIC_IOT_Dataset2023/CSV_FILES/Mirai',
                                '/home/cpitumpeappu/wireless/CSV_DATASETS/CIC_IOT_Dataset2023/CSV_FILES/Benign')
except Exception as e:
    logger.error(f"Error in main execution: {str(e)}")
# print(source.describe())
# print(overall_iot_23.describe())
# print(overall_ciciot.describe())

y = source["Label"]
X = source.drop(['Label'], axis=1)

X = X.replace([np.inf, -np.inf], np.nan)
X = X.fillna(0)
X_train_source, X_test_source, y_train_source, y_test_source = train_test_split(X, y, test_size=0.2, random_state=42)

cv_results_df = perform_cross_validation(models, X, y, cv=5)
cv_results_df.to_csv('./cross_validation_results_mirai.csv', index=False)


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

    with open(f"./{dataset_name}_confusion_matrices_mirai_source.json", 'w') as f:
      json.dump(confusion_matrix_results, f, indent=4)
      f.close()


    return pd.DataFrame(results)

results_df = compare_models(models, X_train_source, X_test_source, y_train_source, y_test_source, "MedBotIoT")
print(results_df)
results_df.to_csv('./model_performance_on_source_mirai.csv')




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


    with open(f"./{dataset_name}_confusion_matrices_target_mirai.json", 'w') as f:
      json.dump(confusion_matrix_results_target, f, indent=4)
      f.close()

    return pd.DataFrame(results)

y = overall_iot_23["Label"]
X = overall_iot_23.drop(['Label'], axis=1)
X = X.replace([np.inf, -np.inf], np.nan)
X = X.fillna(0)
X_train_target, X_test_target, y_train_target, y_test_target = train_test_split(X, y, test_size=0.2, random_state=42)

target_results = evaluate_models_on_target(saved_models, X_test_target, y_test_target,"IoT23")
print("\nModel Performance on IoT23 Dataset as target:")
print(target_results)
target_results.to_csv('./model_performance_on_target_IoT23_MIRAI.csv')

y = overall_ciciot["Label"]
X = overall_ciciot.drop(['Label'], axis=1)

X = X.replace([np.inf, -np.inf], np.nan)
X = X.fillna(0)
X_train_target, X_test_target, y_train_target, y_test_target = train_test_split(X, y, test_size=0.2, random_state=42)

target_results = evaluate_models_on_target(saved_models, X_test_target, y_test_target,"CICIoT")
print("\nModel Performance on CICIoT Dataset as target:")
print(target_results)
target_results.to_csv('./model_performance_on_target_CICIoT_MIRAI.csv')

overall = pd.concat([overall_iot_23,overall_ciciot])



y = overall["Label"]
X = overall.drop(['Label'], axis=1)

X = X.replace([np.inf, -np.inf], np.nan)
X = X.fillna(0)
X_train_target, X_test_target, y_train_target, y_test_target = train_test_split(X, y, test_size=0.2, random_state=42)
target_results = evaluate_models_on_target(saved_models, X_test_target, y_test_target,"IoT23_CICIoT_combined")
print("\nModel Performance on CICIoT Dataset as target:")
print(target_results)
target_results.to_csv('./model_performance_on_both_IoT23_CICIoT_MIRAI.csv')

def get_iot_network_intrusion_datasets():

  iot_network_intrusion_df = pd.read_csv('/home/cpitumpeappu/wireless/CSV_DATASETS/IoT-Network_Intrusion/IoT_Network_Intrusion_Dataset.csv')
  iot_network_intrusion_df.columns = iot_network_intrusion_df.columns.str.replace('_', ' ')

  iot_network_intrusion_mirai_df = iot_network_intrusion_df[iot_network_intrusion_df['Cat'] == 'Mirai']
  iot_network_intrusion_mirai_df = iot_network_intrusion_mirai_df.select_dtypes(include='number')
  iot_network_intrusion_mirai_df = iot_network_intrusion_mirai_df.drop(columns=['Src Port','Dst Port'])
  iot_network_intrusion_mirai_df['Label'] = 1

  iot_network_intrusion_ddos = iot_network_intrusion_df[iot_network_intrusion_df['Cat'] == 'DDoS']
  iot_network_intrusion_ddos = iot_network_intrusion_ddos.select_dtypes(include='number')
  iot_network_intrusion_ddos = iot_network_intrusion_ddos.drop(columns=['Src Port','Dst Port'])
  iot_network_intrusion_ddos['Label'] = 1

  iot_network_intrusion_dos = iot_network_intrusion_df[iot_network_intrusion_df['Cat'] == 'DoS']
  iot_network_intrusion_dos = iot_network_intrusion_dos.select_dtypes(include='number')
  iot_network_intrusion_dos = iot_network_intrusion_dos.drop(columns=['Src Port','Dst Port'])
  iot_network_intrusion_ddos['Label'] = 1


  iot_network_intrusion_normal = iot_network_intrusion_df[iot_network_intrusion_df['Cat'] == 'Normal']
  iot_network_intrusion_normal = iot_network_intrusion_normal.select_dtypes(include='number')
  iot_network_intrusion_normal = iot_network_intrusion_normal.drop(columns=['Src Port','Dst Port'])
  iot_network_intrusion_normal['Label'] = 0


  mirai_w_benign = pd.concat([iot_network_intrusion_mirai_df,iot_network_intrusion_normal])

  ddos_w_benign = pd.concat([iot_network_intrusion_ddos,iot_network_intrusion_normal])

  dos_w_benign = pd.concat([iot_network_intrusion_dos,iot_network_intrusion_normal])

  return mirai_w_benign,ddos_w_benign,dos_w_benign


mirai_w_benign,ddos_w_benign,dos_w_benign = get_iot_network_intrusion_datasets()


print(mirai_w_benign)

y = mirai_w_benign["Label"]
X = mirai_w_benign.drop(['Label'], axis=1)

X = X.replace([np.inf, -np.inf], np.nan)
X = X.fillna(0)
X_train_target, X_test_target, y_train_target, y_test_target = train_test_split(X, y, test_size=0.2, random_state=42)
target_results = evaluate_models_on_target(saved_models, X_test_target, y_test_target,"IoT_Network_Intrusion")
print("\nModel Performance on IoT_Network_Intrusiong Dataset as target:")
print(target_results)
target_results.to_csv('./model_performance_on_target_IoTNetIntrusion_MIRAI.csv')

overall = pd.concat([overall,mirai_w_benign])

y = overall["Label"]
X = overall.drop(['Label'], axis=1)

X = X.replace([np.inf, -np.inf], np.nan)
X = X.fillna(0)
X_train_target, X_test_target, y_train_target, y_test_target = train_test_split(X, y, test_size=0.2, random_state=42)
target_results = evaluate_models_on_target(saved_models, X_test_target, y_test_target,"All_Targets")
print("\nModel Performance on all targets:")
print(target_results)
target_results.to_csv('./model_performance_on_all_targets_MIRAI.csv')
