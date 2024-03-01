import requests
import re
from urllib.parse import urlparse


target_url = input("Enter target URL: ")

def analyze_website(url):
    is_fraudulent = False
    
    # Obtener el contenido
    try:
        response = requests.get(url)
        content = response.text
    except:
        print("\nNo se pudo acceder al sitio web")
        return True
    
    # Analizar la URL
    url_parsed = urlparse(url)
    if not url_parsed.scheme or not url_parsed.netloc:
        print("\nURL inválida")
        is_fraudulent = True
    
    # Buscar indicadores de fraude
    suspicious_words = ["lotería", "premio", "regalo", "dinero gratis"]
    for word in suspicious_words:
        if word in content:
            print("Contenido sospechoso detectado")
            is_fraudulent = True
            break
    
    return is_fraudulent

result = analyze_website(target_url)
if result:
    print("\nEl sitio parece FRAUDULENTO")
else:
    print("\nEl sitio parece LEGÍTIMO")

def fetch_page(url):
    response = requests.get(url)
    return response.text

def analyze_page(page_content):
    vulnerabilities = []
    
    # XSS
    xss_patterns = ["<script>alert(1)</script>", "src=j&Tab;a&Tab;v&Tab;asc&NewLine;ript:alert(&apos;XSS&apos;)"]
    for pattern in xss_patterns:
        if re.search(pattern, page_content):
            vulnerabilities.append("XSS")
            
    # SQL Injection
    sql_patterns = ["Tienes un error en tu sintaxis SQL;", "Advertencia: mysql_fetch_array()"] 
    for pattern in sql_patterns:
        if pattern in page_content:
            vulnerabilities.append("Inyección SQL")
            
    # Shell injection 
    shell_pattern = "El fichero o directorio no existe"
    if shell_pattern in page_content:
        vulnerabilities.append("Inyección de comandos del sistema operativo")
        
    # Directory traversal 
    traversal_pattern = "root:/bin/bash"
    if traversal_pattern in page_content:
        vulnerabilities.append("Recorrido del directorio")
        
    # Cabeceras inseguras
    headers = requests.get(target_url).headers
    if "X-XSS-Protection" not in headers:
        vulnerabilities.append("Encabezados inseguros")
    
    return vulnerabilities

page_content = fetch_page(target_url)
vulnerabilities = analyze_page(page_content) 


print(f"\nVulnerabilidades encontradas en {target_url}: {vulnerabilities}")