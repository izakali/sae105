from flask import Flask, render_template, request
import numpy as np
import os
from collections import Counter
import matplotlib.pyplot as plt

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        # Récupérer le fichier texte depuis le formulaire
        uploaded_file = request.files["file"]
        if uploaded_file.filename != '':
            file_content = uploaded_file.read().decode("utf-8")

            # Votre code existant ici pour traiter les données du fichier texte
            try:
                with open("file.txt", mode="w", encoding="utf8") as file:
                    file.write(file_content)
            except FileNotFoundError:
                return render_template("error.html", message="Le fichier n'existe pas.")

            ress = file_content.split('\n')
            ssh_attempts = 0
            icmp_count = 0

            with open("test.csv", "w") as fic:
                evenement = "DATE;SOURCE;PORT;DESTINATION;FLAG;SEQ"
                fic.write(evenement + "\n")

                for event in ress:
                    if event.startswith('11:42'):
                        seq, heure1, nomip, port, flag = "", "", "", "", ""

                        # Parsing event data
                        texte = event.split(" ")
                        heure1 = texte[0]

                        nomip1 = texte[2].split(".")
                        nomip = ".".join(nomip1[:3])

                        port = texte[2].split(".")[-1]

                        nomip2 = texte[4]

                        texte_flag = event.split("[")
                        if len(texte_flag) > 1:
                            flag = texte_flag[1].split("]")[0]

                        texte_seq = event.split(",")
                        if len(texte_seq) > 1 and texte_seq[1].startswith(" seq"):
                            seq = texte_seq[1].split(" ")[2]

                        evenement = f"{heure1};{nomip};{port};{nomip2};{flag};{seq}"
                        fic.write(evenement + "\n")
                        
                        # Compter uniquement les tentatives SSH en tant que source
                        if "ssh" in event:
                            ssh_attempts += 1

                        if "ICMP echo request" in event:
                            icmp_count += 1

            # Analyser le fichier CSV généré
            data = np.genfromtxt("test.csv", delimiter=';', skip_header=1, dtype=str)

            # Calculer le nombre d'attaques par type
            types_attaques = Counter(data[:, 4])

            # Calculer le nombre de flags de connexion
            nb_flags = Counter(data[:, 4])['S']

            # Calculer la taille du paquet
            taille_paquet = os.path.getsize("test.csv")

            # Trouver les 10 adresses IP les plus fréquentes en tant que source
            adresses_ip_sources_frequentes = Counter(data[:, 1]).most_common(3)

            # Extraire les données pour le graphique à barres
            adresses_ip = [ip for ip, _ in adresses_ip_sources_frequentes]
            occurrences = [count for _, count in adresses_ip_sources_frequentes]

            # Générer le diagramme à barres
            plt.figure(figsize=(10, 6))
            plt.bar(adresses_ip, occurrences, color='blue')
            plt.title('Top 3 Adresses IP Source')
            plt.xlabel('Adresses IP')
            plt.ylabel('Nombre de Paquets')
            plt.xticks(rotation=45)
            plt.tight_layout()

            # Sauvegarder le graphique en tant qu'image
            plt.savefig('static/top_adresses_ip_source.png')

            # Fermer le graphique pour libérer les ressources
            plt.close()

            # Générer le fichier de bilan au format Markdown
            with open("bilan.md", "w") as bilan_file:
                bilan_file.write(f"Type de flags:\n{types_attaques}\n\n")
                bilan_file.write(f"Nombre de flags de connexion [S]: {nb_flags}\n\n")
                bilan_file.write(f"Nombre de tentatives SSH de connexion en tant que source: {ssh_attempts}\n")
                bilan_file.write(f"Nombre de pings ICMP: {icmp_count}\n")
                bilan_file.write(f"Taille du paquet (en octets): {taille_paquet}\n\n")
                bilan_file.write("Top 3 Adresses IP Source:\n")
                for adresse, count in adresses_ip_sources_frequentes:
                    bilan_file.write(f"{adresse}: {count}\n")

                bilan_file.write("\nTop 3 Adresses IP Destination:\n")
                bilan_file.write("![Top 3 Adresses IP Source](static/top_adresses_ip_source.png)\n")


            # Lire le contenu du fichier Markdown généré
            with open("bilan.md", "r") as bilan_file:
                markdown_content = bilan_file.read()

            return render_template("result.html", markdown_content=markdown_content)

    return render_template("index.html")

if __name__ == "__main__":
    app.run(debug=True)