import requests

print("Realizando em rota do Csharp")
# URL da API que aceita a criação de comentários
url = 'http://localhost:5257/api/Auth/login'
headers = {
    'accept': 'application/json',
    'Content-Type': 'application/json'
}

# Payload XSS
payload = '<script>alert("XSS Attack!");</script>'

# Dados a serem enviados na solicitação
data = {
    'username': '123',
    'password': payload
}

# Enviando a solicitação POST com o payload malicioso
response = requests.post(url, json=data, headers=headers)

# Exibindo a resposta para verificar se o payload foi aceito
print(response.json())

print("Realizando em rota do flask")
# URL da API que aceita a criação de comentários
url = 'http://127.0.0.1:5000/login'
headers = {
    'accept': 'application/json',
    'Content-Type': 'application/json'
}

# Payload XSS
payload = '<script>alert("XSS Attack!");</script>'

# Dados a serem enviados na solicitação
data = {
    'username': payload,
    'password': 'password'
}

# Enviando a solicitação POST com o payload malicioso
response = requests.post(url, json=data, headers=headers)

# Exibindo a resposta para verificar se o payload foi aceito
print(response.json())

print("Realizando em rota do golang")
# URL da API que aceita a criação de comentários
url = 'http://localhost:8080/login'
headers = {
    'accept': 'application/json',
    'Content-Type': 'application/json'
}

# Payload XSS
payload = '<script>alert("XSS Attack!");</script>'

# Dados a serem enviados na solicitação
data = {
    'username': payload,
    'password': 'password'
}

# Enviando a solicitação POST com o payload malicioso
response = requests.post(url, json=data, headers=headers)

# Exibindo a resposta para verificar se o payload foi aceito
print(response.json())

print("Inicando teste no FastApi")

# URL da API
url = 'http://localhost:8000/token'

# Payload para verificação
data = {
    'grant_type': '',
    'username': 'test<script>alert("XSS Test");</script>',
    'password': 'password',
    'scope': '',
    'client_id': '',
    'client_secret': ''
}

# Enviando a solicitação POST
response = requests.post(url, data=data, headers={
    'accept': 'application/json',
    'Content-Type': 'application/x-www-form-urlencoded'
})

print(response.text)

print("Realizando em rota do FastApi2")
# URL da API que aceita a criação de comentários
url = 'http://localhost:7500/token'
headers = {
    'accept': 'application/json',
    'Content-Type': 'application/json'
}

# Payload XSS
payload = '<script>alert("XSS Attack!");</script>'

# Dados a serem enviados na solicitação
data = {
    'username': "testuser",
    'password': 'password'
}

# Enviando a solicitação POST com o payload malicioso
response = requests.post(url, json=data, headers=headers)

url = "http://localhost:7500/profile?username=testuser<script>alert('XSS Attack!');</script>"

result = response.json()
print(result)
headers = {
    'accept': 'application/json',
    'Content-Type': 'application/json',
    'Authorization': f"Bearer {result['access_token']}"
}

# Enviando a solicitação POST com o payload malicioso
response = requests.get(url)

# Exibindo a resposta para verificar se o payload foi aceito
print(response.text)
