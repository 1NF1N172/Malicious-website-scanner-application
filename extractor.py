import requests  # Библиотеката 'requests' позволява извършване на HTTP заявки за извличане на данни от уебсайтове.
from bs4 import BeautifulSoup  # 'BeautifulSoup' е библиотека за парсинг на HTML и XML документи, улесняваща извличането на данни.
import whois  # 'whois' позволява извличане на информация за домейни, включително собственик и дата на регистрация.
import tldextract  # 'tldextract' анализира домейн имена, извличайки основната част на домейна и TLD.
import validators  # 'validators' предоставя функции за валидиране на URL адреси и имейли.
import re  # Модулът 're' предлага функции за работа с регулярни изрази за търсене и валидиране на текст.
import socket  # 'socket' е модул за работа с мрежи, позволяващ създаването на мрежови приложения и манипулиране на сокети.
from urllib.parse import urlparse  # 'urlparse' предоставя функции за парсинг на URL адреси и извличане на компоненти.
import csv  # Модулът 'csv' позволява работа с CSV файлове за четене и запис на данни.
import os  # 'os' предоставя функции за работа с файловата система и управление на операционната система.

def get_url_features(url):
    """
    Анализира предоставен URL адрес и извлича различни характеристики за оценка на потенциалните рискове.
    """
    features = {}

    if not validators.url(url):
        return {"error": "Invalid URL"}

    # URL разбор
    parsed_url = urlparse(url)
    hostname = parsed_url.hostname
    path = parsed_url.path
    scheme = parsed_url.scheme

    features['url'] = url
    features['length_url'] = len(url)
    features['length_hostname'] = len(hostname) if hostname else 0

    # URL компоненти
    features['nb_dots'] = url.count('.')
    features['nb_hyphens'] = url.count('-')
    features['nb_at'] = url.count('@')
    features['nb_qm'] = url.count('?')
    features['nb_and'] = url.count('&')
    features['nb_or'] = url.count('|')
    features['nb_eq'] = url.count('=')
    features['nb_underscore'] = url.count('_')
    features['nb_tilde'] = url.count('~')
    features['nb_percent'] = url.count('%')
    features['nb_slash'] = url.count('/')
    features['nb_star'] = url.count('*')
    features['nb_colon'] = url.count(':')
    features['nb_comma'] = url.count(',')
    features['nb_semicolon'] = url.count(';')
    features['nb_dollar'] = url.count('$')
    features['nb_space'] = url.count(' ')
    features['nb_www'] = url.count('www')
    features['nb_com'] = url.count('.com')
    features['nb_dslash'] = url.count('//')

    # Инспектиране на съмнителни часи в домейна
    suspicious_keywords = ['gooogle', 'g0ogle', 'g00gle', 'gogle', 'g0gle', '2secure', 'banking', 'login']
    features['domain_suspicious'] = 'Yes' if any(keyword in hostname for keyword in suspicious_keywords) else 'No'

    # Проверка на SSL 
    features['https'] = 'Yes' if scheme == 'https' else 'No'

    # Domain информация
    try:
        if hostname:
            domain_info = whois.whois(hostname)
            creation_date = domain_info.creation_date
            expiration_date = domain_info.expiration_date

            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            if isinstance(expiration_date, list):
                expiration_date = expiration_date[0]

            if creation_date and expiration_date:
                features['domain_age'] = (expiration_date - creation_date).days // 365  # Изчислява възрастта на домейна
                features['domain_registration_length'] = (expiration_date - creation_date).days // 30  # Изчислява дължината на регистрацията на домейна
            else:
                features['domain_age'] = 0
                features['domain_registration_length'] = 0
            
            features['whois_registered_domain'] = 'Yes'  # Проверява дали домейнът е регистриран
        else:
            features['domain_age'] = 0
            features['domain_registration_length'] = 0
            features['whois_registered_domain'] = 'No'  # Няма хост
    except Exception as e:
        features['domain_age'] = 0
        features['domain_registration_length'] = 0
        features['whois_registered_domain'] = 'No'  # Неуспех в получаване на информация за домейна
        print(f"Domain information error: {e}")

    features['punycode'] = 'Yes' if re.search(r'x{2,}', url) else 'No'  # Проверява за Punycode в URL


    # Проверява IP адреса на хоста и извлича характеристиките на пътя на URL
    try:
        if hostname:
            ip_address = socket.gethostbyname(hostname)  # Получава IP адреса на хоста
            features['ip'] = ip_address  # Записва IP адреса в характеристиките
        else:
            features['ip'] = '0'  # Няма хост, задава '0'
    except Exception as e:
        features['ip'] = '0'  # При грешка задава '0'
        print(f"IP resolution error: {e}")  # Печата грешка

    # URL Path Characteristics
    features['http_in_path'] = 'Yes' if 'http' in path else 'No'  # Проверява наличие на 'http' в пътя
    features['https_token'] = 'Yes' if 'https' in url else 'No'  # Проверява наличие на 'https' в URL
    features['ratio_digits_url'] = sum(c.isdigit() for c in url) / len(url) if len(url) > 0 else 0  # Изчислява дял на цифрите в URL
    features['ratio_digits_host'] = sum(c.isdigit() for c in hostname) / len(hostname) if hostname and len(hostname) > 0 else 0  # Изчислява дял на цифрите в хоста

    # Extract subdomains
    ext = tldextract.extract(url)  # Извлича поддомейните от URL
    features['nb_subdomains'] = len(ext.subdomain.split('.')) if ext.subdomain else 0  # Брои поддомените
    features['abnormal_subdomain'] = 'Yes' if len(ext.subdomain) > 15 else 'No'  # Проверява за аномалии в поддомените

     # Извлича HTML съдържанието на страницата и анализира линковете и медийните ресурси
    try:
        response = requests.get(url)  # Изпраща GET заявка към URL
        soup = BeautifulSoup(response.text, 'html.parser')  # Парсва HTML съдържанието

        # Links and Media
        links = soup.find_all('a')  # Намира всички линкове на страницата
        features['nb_hyperlinks'] = len(links)  # Брои броя на линковете
        features['ratio_intHyperlinks'] = len([l for l in links if l.get('href', '').startswith(url)]) / len(links) if len(links) > 0 else 0  # Изчислява дял на вътрешните линкове
        features['ratio_extHyperlinks'] = len([l for l in links if not l.get('href', '').startswith(url)]) / len(links) if len(links) > 0 else 0  # Изчислява дял на външните линкове
        features['nb_extCSS'] = len([l for l in soup.find_all('link') if l.get('rel') == ['stylesheet'] and l.get('href') and not l.get('href').startswith(url)])  # Брои външните CSS файлове

       
        # Извлича текстово съдържание от страницата и анализира различни характеристики
        content = soup.get_text()  # Извлича текстовото съдържание на страницата
        features['poor_grammar'] = 'Yes' if re.search(r'\b(?:mistake|error|spelling|grammatical)\b', content, re.IGNORECASE) else 'No'  # Проверява за лоша граматика
        features['compare_with_official'] = 'No'  # Няма сравнение с официални сайтове, изискващо разширен анализ

        features['login_form'] = 'Yes' if soup.find('form') and any('login' in (attr or '').lower() for attr in [f.get('action') for f in soup.find_all('form')]) else 'No'  # Проверява наличието на форма за вход
        features['sfh'] = 'Yes' if soup.find('form') and all(f.get('action') and not f.get('action').startswith(url) for f in soup.find_all('form')) else 'No'  # Проверява дали формата не се изпраща на същия хост
        features['iframe'] = 'Yes' if soup.find_all('iframe') else 'No'  # Проверява наличието на iframe елементи
        features['popup_window'] = 'Yes' if soup.find_all('script') and any('window.open' in script.get_text() for script in soup.find_all('script')) else 'No'  # Проверява дали страницата създава изскачащи прозорци
        features['empty_title'] = 'Yes' if not soup.title or not soup.title.string.strip() else 'No'  # Проверява дали заглавието на страницата е празно
        features['domain_in_title'] = 'Yes' if hostname and hostname in (soup.title.string if soup.title else '') else 'No'  # Проверява дали домейнът е в заглавието на страницата
        features['external_favicon'] = 'Yes' if soup.find('link', rel='icon') and not soup.find('link', rel='icon').get('href', '').startswith(url) else 'No'  # Проверява наличието на външен favicon
        features['submit_email'] = 'Yes' if soup.find('form') and any('email' in (input.get('type') or '').lower() for input in soup.find_all('input')) else 'No'  # Проверява дали има поле за изпращане на имейл

    # Обработва грешки при анализа на съдържанието и задава стойности по подразбиране
    except Exception as e:
        features['nb_hyperlinks'] = 0  # Броят на хипервръзките е зададен на 0
        features['ratio_intHyperlinks'] = 0  # Съотношението на вътрешни хипервръзки е зададено на 0
        features['ratio_extHyperlinks'] = 0  # Съотношението на външни хипервръзки е зададено на 0
        features['nb_extCSS'] = 0  # Броят на външните CSS файлове е зададен на 0
        features['login_form'] = 'No'  # Няма форма за вход
        features['sfh'] = 'No'  # Няма форма с цел за действие на същия хост
        features['iframe'] = 'No'  # Няма iframe елементи
        features['popup_window'] = 'No'  # Няма отварящи се прозорци
        features['empty_title'] = 'Yes'  # Заглавието е празно
        features['domain_in_title'] = 'No'  # Домейнът не е в заглавието
        features['external_favicon'] = 'No'  # Няма външен favicon
        features['submit_email'] = 'No'  # Няма поле за изпращане на имейл
        features['poor_grammar'] = 'No'  # Няма лоша граматика
        features['compare_with_official'] = 'No'  # Няма сравнение с официални сайтове
        print(f"Page content analysis error: {e}")  # Извежда грешката при анализа на съдържанието

    return features  # Връща характеристиките

def auto_detect_phishing(features):
    # Проверка на HTTPS
    if features['https'] == 'No':
        return 'phishing'  # Уебсайтът е фишинг, ако не използва HTTP
    # Инспекция на домейна
    if features['domain_suspicious'] == 'Yes':
        return 'phishing'  # Уебсайтът е фишинг, ако домейнът е подозрителен
    # Възраст на домейна
    if features['domain_age'] < 1:
        return 'phishing'  # Уебсайтът е фишинг, ако домейнът е по-млад от 1 година
    # Поддомейни
    if features['nb_subdomains'] > 3:
        return 'phishing'  # Уебсайтът е фишинг, ако има повече от 3 поддомейна
    # Форма за вход и SFH
    if features['login_form'] == 'Yes' and features['sfh'] == 'Yes':
        return 'phishing'  # Уебсайтът е фишинг, ако има форма за вход и действие за подаване на форма на различен домейн
    # Хипервръзки
    if features['nb_hyperlinks'] > 30:
        return 'phishing'  # Уебсайтът е фишинг, ако има повече от 30 хипервръзки
    # Външен favicon
    if features['external_favicon'] == 'Yes':
        return 'phishing'  # Уебсайтът е фишинг, ако favicon не е от същия домейн
    # Дължина и структура на URL
    if features['length_hostname'] < 6:
        return 'phishing'  # Уебсайтът е фишинг, ако името на хоста е по-кратко от 6 символа
    if features['ratio_digits_url'] > 0.3:
        return 'phishing'  # Уебсайтът е фишинг, ако повече от 30% от URL-то съдържа цифри
    # Лоша граматика
    if features['poor_grammar'] == 'Yes':
        return 'phishing'  # Уебсайтът е фишинг, ако има индикации за лоша граматика
    # Сравнение с официални сайтове (опростена проверка)
    if features['compare_with_official'] == 'No':
        return 'phishing'  # Уебсайтът е фишинг, ако не може да се сравни с официални сайтове
    # По подразбиране е легитимен, ако няма нито един от червените флагове
    return 'legitimate'  # Уебсайтът се счита за легитимен

def add_to_dataset(features, label='legitimate'):
    # Уверете се, че директорията на набора от данни съществува
    dataset_dir = 'datasets'
    if not os.path.exists(dataset_dir):
        os.makedirs(dataset_dir)

    file_path = os.path.join(dataset_dir, 'phishing_dataset.csv')
    
    # Запис в CSV файл
    try:
        with open(file_path, mode='a', newline='') as file:
            writer = csv.writer(file)
            row = [
                features.get('url', ''),  # URL адрес
                features.get('length_url', 0),  # Дължина на URL адреса
                features.get('length_hostname', 0),  # Дължина на домейна
                features.get('nb_dots', 0),  # Брой точки в URL
                features.get('nb_hyphens', 0),  # Брой тирета в URL
                features.get('nb_at', 0),  # Брой символи @
                features.get('nb_qm', 0),  # Брой ? в URL
                features.get('nb_and', 0),  # Брой & в URL
                features.get('nb_or', 0),  # Брой | в URL
                features.get('nb_eq', 0),  # Брой = в URL
                features.get('nb_underscore', 0),  # Брой _ в URL
                features.get('nb_tilde', 0),  # Брой ~ в URL
                features.get('nb_percent', 0),  # Брой % в URL
                features.get('nb_slash', 0),  # Брой / в URL
                features.get('nb_star', 0),  # Брой * в URL
                features.get('nb_colon', 0),  # Брой : в URL
                features.get('nb_comma', 0),  # Брой , в URL
                features.get('nb_semicolon', 0),  # Брой ; в URL
                features.get('nb_dollar', 0),  # Брой $ в URL
                features.get('nb_space', 0),  # Брой пространства в URL
                features.get('nb_www', 0),  # Брой www в URL
                features.get('nb_com', 0),  # Брой .com в URL
                features.get('nb_dslash', 0),  # Брой // в URL
                features.get('domain_suspicious', ''),  # Подозрителен домейн
                features.get('https', ''),  # Използва ли HTTPS
                features.get('domain_age', 0),  # Възраст на домейна
                features.get('domain_registration_length', 0),  # Дължина на регистрацията на домейна
                features.get('whois_registered_domain', ''),  # Регистриран ли е домейнът
                features.get('punycode', ''),  # Съдържа ли Punycode
                features.get('ip', ''),  # IP адрес
                features.get('http_in_path', ''),  # Съдържа ли HTTP в пътя
                features.get('https_token', ''),  # Съдържа ли HTTPS токен
                features.get('ratio_digits_url', 0),  # Процент на цифрите в URL
                features.get('ratio_digits_host', 0),  # Процент на цифрите в домейна
                features.get('nb_subdomains', 0),  # Брой поддомейни
                features.get('abnormal_subdomain', ''),  # Ненормален поддомейн
                features.get('nb_hyperlinks', 0),  # Брой хипервръзки
                features.get('ratio_intHyperlinks', 0),  # Процент на вътрешни хипервръзки
                features.get('ratio_extHyperlinks', 0),  # Процент на външни хипервръзки
                features.get('nb_extCSS', 0),  # Брой външни CSS
                features.get('poor_grammar', ''),  # Лоша граматика
                features.get('compare_with_official', ''),  # Сравнение с официални сайтове
                features.get('login_form', ''),  # Налична ли е форма за вход
                features.get('sfh', ''),  # Сигурност на формата за вход
                features.get('iframe', ''),  # Налични ли са iframe
                features.get('popup_window', ''),  # Налични ли са поп-ъп прозорци
                features.get('empty_title', ''),  # Празен ли е заглавието
                features.get('domain_in_title', ''),  # Доменът присъства ли в заглавието
                features.get('external_favicon', ''),  # Външен ли е favicon
                features.get('submit_email', ''),  # Наличен ли е бутон за изпращане на имейл
                label  # Етикет (легитимен или фишинг)
            ]
            writer.writerow(row)  # Записва реда в CSV
        print("Data successfully saved to dataset.")  # Успешно записване
    except Exception as e:
        print(f"Error saving to dataset: {e}")  # Грешка при записването

if __name__ == "__main__":  # Проверява дали файлът се изпълнява като основна програма
    while True:  # Безкраен цикъл за въвеждане на URL адреси
        url = input("Enter a URL (or type 'exit' to quit): ")  # Изисква от потребителя да въведе URL адрес или да напише 'exit' за изход
        if url.lower() == 'exit':  # Проверява дали потребителят иска да излезе
            break  # Излиза от цикъла, ако е избрано 'exit'
        
        features = get_url_features(url)  # Извлича характеристики на предоставения URL адрес
        if 'error' in features:  # Проверява дали има грешка в извлечените характеристики
            print(features['error'])  # Извежда съобщение за грешка
            continue  # Продължава с следващото въвеждане на URL адрес
        
        print("\nFeatures extracted:")  # Извежда заглавие за характеристиките
        for key, value in features.items():  # Итерация през всички извлечени характеристики
            print(f"{key}: {value}")  # Извежда името и стойността на характеристиката

        detected_label = auto_detect_phishing(features)  # Автоматично открива дали URL адресът е фишинг
        print(f"\nAutomatic phishing detection suggests this URL is: {detected_label}")  # Извежда предложеното откритие на фишинг

        confirm_label = input("Confirm the label for the dataset (1: phishing, 2: legitimate): ")  # Пита потребителя да потвърди етикета за запис в набора от данни
        if confirm_label == '1':  # Проверява дали потребителят избира фишинг
            label = 'phishing'  # Задава етикет 'фишинг'
        elif confirm_label == '2':  # Проверява дали потребителят избира легитимен
            label = 'legitimate'  # Задава етикет 'легитимен'
        else:  # Обработка на невалиден вход
            print("Invalid input, skipping this URL.")  # Извежда съобщение за невалиден вход
            continue  # Продължава с следващото въвеждане на URL адрес

        add_to_dataset(features, label)  # Записва характеристиките и потвърдения етикет в набора от данни
        print(f"\nURL features and label '{label}' added to the dataset.")  # Извежда съобщение за успешно добавяне в набора от данни
