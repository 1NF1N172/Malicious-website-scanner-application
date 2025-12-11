import pandas as pd
from sklearn.model_selection import train_test_split, GridSearchCV, StratifiedKFold  
from sklearn.ensemble import RandomForestClassifier  
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix, roc_auc_score  
from sklearn.preprocessing import StandardScaler, LabelEncoder 
from imblearn.over_sampling import SMOTE  
import pickle  
from sklearn.impute import SimpleImputer
from features import calculate_entropy

# лоадване на дайтасета
def load_data(file_path): 
    data = pd.read_csv(file_path)  
    print("Total number of rows (including header):", data.shape[0])  
    print("Total number of columns:", data.shape[1])  
    print("First few rows of data:")  
    print(data.head(10))  
    return data  

def preprocess_data(data):
    desired_features = [
        'url', 'length_url', 'length_hostname', 'ip', 'nb_dots', 'nb_hyphens', 'nb_at', 
        'nb_qm', 'nb_and', 'nb_or', 'nb_eq', 'nb_underscore', 'nb_tilde', 'nb_percent', 
        'nb_slash', 'nb_star', 'nb_colon', 'nb_comma', 'nb_semicolumn', 'nb_dollar', 
        'nb_space', 'nb_www', 'nb_com', 'nb_dslash', 'http_in_path', 'https_token', 
        'ratio_digits_url', 'ratio_digits_host', 'punycode', 'port', 'tld_in_path', 
        'tld_in_subdomain', 'abnormal_subdomain', 'nb_subdomains', 'prefix_suffix', 
        'random_domain', 'shortening_service', 'path_extension', 'nb_redirection', 
        'nb_external_redirection', 'length_words_raw', 'char_repeat', 'shortest_words_raw', 
        'shortest_word_host', 'shortest_word_path', 'longest_words_raw', 
        'longest_word_host', 'longest_word_path', 'avg_words_raw', 'avg_word_host', 
        'avg_word_path', 'phish_hints', 'domain_in_brand', 'brand_in_subdomain', 
        'brand_in_path', 'suspicious_tld', 'statistical_report', 'nb_hyperlinks', 
        'ratio_inthyperlinks', 'ratio_exthyperlinks', 'ratio_nullhyperlinks', 
        'nb_extcss', 'ratio_intredirection', 'ratio_exteredirection', 
        'ratio_interrors', 'ratio_exterrors', 'login_form', 'external_favicon', 
        'links_in_tags', 'submit_email', 'ratio_intmedia', 'ratio_extmedia', 'sfh', 
        'iframe', 'popup_window', 'safe_anchor', 'onmouseover', 
        'right_clic', 'empty_title', 'domain_in_title', 'domain_with_copyright', 
        'whois_registered_domain', 'domain_registration_length', 'domain_age', 
        'web_traffic', 'dns_record', 'google_index', 'page_rank', 'status'
    ]

    data.columns = data.columns.str.strip().str.lower()
    data['url_entropy'] = data['url'].apply(calculate_entropy)

    y = data['status']
    y_encoded = LabelEncoder().fit_transform(y)  

    available_features = [feature for feature in desired_features if feature in data.columns]
    print("Available features in the dataset:", available_features)

    X = data[available_features].copy() 
    numeric_columns = X.select_dtypes(include=['number']).columns.tolist()
    categorical_columns = X.select_dtypes(include=['object']).columns.tolist()

    # Приписване на липсващи стойности
    imputer_numeric = SimpleImputer(strategy='median')
    X_numeric = imputer_numeric.fit_transform(X[numeric_columns])

    imputer_categorical = SimpleImputer(strategy='most_frequent')
    X_categorical = imputer_categorical.fit_transform(X[categorical_columns])

    X_numeric = pd.DataFrame(X_numeric, columns=numeric_columns)
    X_categorical = pd.DataFrame(X_categorical, columns=categorical_columns)

    # Стандартизирайте числовите функции
    scaler = StandardScaler()
    X_numeric = scaler.fit_transform(X_numeric)

    if len(categorical_columns) > 0:
        X_categorical = pd.get_dummies(X_categorical, drop_first=True)

    X_final = pd.concat([pd.DataFrame(X_numeric), X_categorical], axis=1)

    print("Shape of X after preprocessing:", X_final.shape)  # Очакване (n, m)
    print("Shape of y after preprocessing:", y_encoded.shape)  # Очаквам (n,)
    
    return X_final.values, y_encoded

def create_lookup_table(data):
    lookup_table = data[['url', 'status']].drop_duplicates().set_index('url').to_dict()['status']
    return lookup_table

def train_and_save_model(file_path, model_path, lookup_table_path):
    data = load_data(file_path)
    
    # Проверете данните след зареждане
    print("Data shape after loading:", data.shape)  

    X, y = preprocess_data(data)

    lookup_table = create_lookup_table(data)
    with open(lookup_table_path, 'wb') as file:
        pickle.dump(lookup_table, file)
    print(f"Look-up table saved to {lookup_table_path}")

    # Приложете SMOTE
    smote = SMOTE(random_state=42)
    X_resampled, y_resampled = smote.fit_resample(X, y)

    # Проверете фигурите след SMOTE
    print("Shape of X after SMOTE:", X_resampled.shape)
    print("Shape of y after SMOTE:", y_resampled.shape)

    # Разделете данните на набори за обучение и тестване
    X_train, X_test, y_train, y_test = train_test_split(X_resampled, y_resampled, test_size=0.3, random_state=42, stratify=y_resampled)

    # Проверете формите на комплекти за обучение и тестване
    print("Shape of X_train:", X_train.shape)
    print("Shape of X_test:", X_test.shape)
    print("Shape of y_train:", y_train.shape)
    print("Shape of y_test:", y_test.shape)

    # обучение  RandomForest model
    rf_model = RandomForestClassifier(random_state=42)

    # Хиперпараметрична настройка
    param_grid = {
        'n_estimators': [100, 200, 300, 500], #броят на дърветата.
        'max_features': ['sqrt', 'log2'], #характеристиките, които ще се използват за изграждането на всяко дърво. (sqrt -  квадратният корен от общия брой характеристики; лог2логаритъм с основа 2 от общия брой характеристики)
        'max_depth': [None, 10, 20, 30], #Максималната дълбочина на всяко дърво в ансамбъла.  контролира колко дълбоко може да расте всяко дърво, т.е. колко пъти дървото може да разделя данните, докато не достигне лист.
        'min_samples_split': [2, 5, 10], #Минималният брой примери, необходими за разделяне на възел  Контролира кога да се спре разделянето на даден възел в дървото
        'min_samples_leaf': [1, 2, 4],  # Минималният брой примери, необходими за съществуване на лист. Контролира кога да се спре растежа на дърветата.
        'class_weight': [None, 'balanced']  #контролира как се обработват класовете в небалансирани задачи.
    }

    cv = StratifiedKFold(n_splits=5)

    grid_search = GridSearchCV(estimator=rf_model, param_grid=param_grid, cv=cv, n_jobs=-1, verbose=2, scoring='roc_auc')
    grid_search.fit(X_train, y_train)
    
    best_rf_model = grid_search.best_estimator_

    with open(model_path, 'wb') as file:
        pickle.dump(best_rf_model, file)
    print(f"RandomForest model saved to {model_path}")

    # Оценка
    y_pred_rf = best_rf_model.predict(X_test)
    y_pred_proba_rf = best_rf_model.predict_proba(X_test)[:, 1]

    print("RandomForest Best Parameters:", grid_search.best_params_)
    print("RandomForest Accuracy Score:", accuracy_score(y_test, y_pred_rf))
    print("RandomForest Confusion Matrix:\n", confusion_matrix(y_test, y_pred_rf))
    print("RandomForest ROC AUC Score:", roc_auc_score(y_test, y_pred_proba_rf))
    print("RandomForest Classification Report:\n", classification_report(y_test, y_pred_rf))

# Пътища за набор от данни и модели
dataset_path = 'datasets/phishing_dataset.csv' 
model_path = 'models/RandomForest.pickle'
lookup_table_path = 'models/lookup_table.pickle'

train_and_save_model(dataset_path, model_path, lookup_table_path)
