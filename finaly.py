import numpy as np
import os
from collections import Counter

try:
    with open("zbi.txt", encoding="utf8") as fh:
        res = fh.read()
except FileNotFoundError:
    print(f"Le fichier n'existe pas {os.path.abspath('file.txt')}")

ress = res.split('\n')
tab_dest = np.array([])
ssh_attempts = 0  # Ajout d'une variable pour compter les tentatives SSH
icmp_count = 0  # Ajout d'une variable pour compter les pings ICMP

with open("wsh.csv", "w") as fic:
    evenement = "DATE;SOURCE;PORT;DESTINATION;FLAG;SEQ"
    fic.write(evenement + "\n")

    for event in ress:
        if event.startswith('02:4'):
            seq, heure1, nomip, port, flag = "", "", "", "", ""

            # Parsing event data
            texte = event.split(" ")
            heure1 = texte[0]

            nomip1 = texte[2].split(".")
            nomip = ".".join(nomip1[:3])

            if nomip not in tab_dest:
                tab_dest = np.append(tab_dest, nomip)

            port = texte[2].split(".")[-1]

            nomip2 = texte[4]

            texte_flag = event.split("[")
            if len(texte_flag) > 1:
                flag = texte_flag[1].split("]")[0]

                if port == "ssh" and flag == "S":
                    ssh_attempts += 1

            texte_seq = event.split(",")
            if len(texte_seq) > 1 and texte_seq[1].startswith(" seq"):
                seq = texte_seq[1].split(" ")[2]

            evenement = f"{heure1};{nomip};{port};{nomip2};{flag};{seq}"
            fic.write(evenement + "\n")

            if "ICMP echo request" in event:
                icmp_count += 1

# Analyser le fichier CSV généré
data = np.genfromtxt("wsh.csv", delimiter=';', skip_header=1, dtype=str)

# Calculer le nombre d'attaques par type
types_attaques = Counter(data[:, 4])
print("Types d'attaques et leur fréquence:")
for attaque, count in types_attaques.items():
    print(f"{attaque}: {count}")

# Calculer le nombre de flags de connexion
nb_flags = Counter(data[:, 4])['S']

# Calculer la taille du paquet
taille_paquet = os.path.getsize("wsh.csv")

# Trouver les 10 adresses IP les plus fréquentes
adresses_ip_frequentes = Counter(data[:, 3]).most_common(10)
print("\nTop 10 adresses IP les plus fréquentes:")
for adresse, count in adresses_ip_frequentes:
    print(f"{adresse}: {count}")

# Générer le fichier de bilan
with open("wsh.md", "w") as bilan_file:
    bilan_file.write(f"Type de flags:\n{types_attaques}\n\n")
    bilan_file.write(f"Nombre de flags de connexion [S]: {nb_flags}\n\n")
    bilan_file.write(f"Nombre de tentatives SSH de connexion: {ssh_attempts}\n")
    bilan_file.write(f"Nombre de pings ICMP: {icmp_count}\n")

    bilan_file.write(f"Taille du paquet (en octets): {taille_paquet}\n\n")
    bilan_file.write("Top 10 adresses IP les plus fréquentes:\n")
    for adresse, count in adresses_ip_frequentes:
        bilan_file.write(f"{adresse}: {count}\n")
