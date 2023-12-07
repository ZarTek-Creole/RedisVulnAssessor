## Caractéristiques Principales

- **Détection Automatisée** : Identifie rapidement les instances Redis vulnérables et accessibles.
- **Exploitation des Vulnérabilités** : Utilise des techniques avancées pour exploiter les faiblesses courantes dans les configurations Redis.
- **Rapports de Sécurité** : Génère des rapports clairs et détaillés sur les failles détectées et les recommandations pour les corriger.
- **Interface Utilisateur Conviviale** : Facile à utiliser, même pour les personnes ayant une connaissance limitée de Redis.
- **Compatibilité** : Compatible avec divers environnements et versions de Redis.

## Installation

```bash
# Cloner le dépôt
git clone https://github.com/ZarTek-Creole/RedisVulnAssessor.git

# Se déplacer dans le dossier du projet
cd RedisVulnAssessor

# Installation des dépendances (si nécessaire)
pip install -r requirements.txt
```

## Utilisation

```bash
# Lancer l'outil avec une adresse IP spécifique
python RedisVulnAssessor.py --ip <adresse_ip>

# Lancer l'outil avec un fichier contenant des adresses IP
python RedisVulnAssessor.py -f <chemin_du_fichier>

# Pour plus d'options
python RedisVulnAssessor.py --help
```

## Contribution

Les contributions au projet sont les bienvenues. Si vous souhaitez contribuer, veuillez forker le dépôt et proposer une pull request.

## Licence

Ce projet est sous licence [MIT](LICENSE).

## Avertissement

Cet outil est destiné à des fins éducatives et de test de sécurité. L'utilisation de cet outil sur des réseaux ou des serveurs sans autorisation explicite est illégale. L'auteur ou les contributeurs ne seront pas responsables de toute utilisation illégale.

## Contact

Pour toute question ou suggestion, n'hésitez pas à contacter [ZarTek-Creole](https://github.com/ZarTek-Creole).

---

RedisVulnAssessor © 2023 par [ZarTek-Creole](https://github.com/ZarTek-Creole). Tous droits réservés.
