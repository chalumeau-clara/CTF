from flask import Flask, send_file

app = Flask(__name__)

# Endpoint pour servir le fichier
@app.route('/Holmes/Enigma.ps1')
def download_enigma():
    return send_file('Holmes/Enigma.ps1', as_attachment=True)

# Send the file that encrypt the wanted file
@app.route('/Holmes/Encrypt.ps1')
def download_encrypt():
    return send_file('Holmes/Encrypt.ps1', as_attachment=True)

# Send fake place offer
@app.route('/Holmes/Tirage_au_sort_pour_gagner_des_places_aux_Jeux_Olympiques_de_Paris_2024.pdf')
def download_pdf():
    return send_file('Holmes/Tirage_au_sort_pour_gagner_des_places_aux_Jeux_Olympiques_de_Paris_2024.pdf', as_attachment=True)

# Send the key that serve for encrypted the system
@app.route('/Holmes/key.txt')
def download_key():
    return send_file('Holmes/key.txt', as_attachment=True)

# Send the get file info script
@app.route('/Holmes/GetFileInfo.ps1')
def download_FileInfo():
    return send_file('Holmes/GetFileInfo.ps1', as_attachment=True)

# Wallpaper
@app.route('/Holmes/wallpaper.jpg')
def download_wallpaper():
    return send_file('Holmes/wallpaper.jpg', as_attachment=True)

# Endpoint pour servir le fichier
def start():
    # Remplacez 'chemin/vers/monfichier.ext' par le chemin de votre fichier
    return send_file('test/flag.txt', as_attachment=True)

# Démarrage du serveur
if __name__ == '__main__':
    # Spécifiez l'adresse IP (par exemple, '0.0.0.0' pour écouter sur toutes les interfaces)
    # Vous pouvez également spécifier une adresse IP spécifique comme '192.168.1.2'
    app.run(debug=True, host='0.0.0.0', port=5000)