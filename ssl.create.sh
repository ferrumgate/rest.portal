read -p 'domain ismi giriniz' domain

openssl req -x509 -nodes -days 3650 -newkey rsa:2048 -keyout ${domain}.key -out ${domain}.crt -subj "/CN=${domain}/O=${domain}"