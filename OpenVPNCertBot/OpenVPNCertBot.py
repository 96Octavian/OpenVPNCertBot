#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
"""
Manage your certificate on your VPN with this bot
"""

# TODO: Better comment
# TODO: Better logging
# TODO: Add license and credits
# TODO: Allow owner to remove users
# TODO: Improve instructions and info
# TODO: extract openvpn server info for client configuration (i.e. to populate default.txt)

import json
import logging
import os
import shutil
from systemd.journal import JournaldLogHandler as JournalHandler
import subprocess
import sys
import threading

from signal import (signal, SIGINT, SIGTERM, SIGABRT, SIGUSR1, SIGUSR2)
from time import sleep

from telegram.ext import (Updater, CommandHandler, Filters)

# Enable logging
logger = logging.getLogger(__file__.replace('.py', ''))

logging.basicConfig(format='%(asctime)s %(name)s - %(levelname)s: %(message)s', level=logging.INFO)

logging.propagate = 0

log_fmt = logging.Formatter('%(levelname)s: %(message)s')
log_ch = JournalHandler(identifier='OpenVPNCertBot')
log_ch.setFormatter(log_fmt)
logger.addHandler(log_ch)


class FilesContainer:
    def __init__(self):
        self.lock = threading.Lock()
        self.users_list = []
        self.users = {}
        self.certs = []
        self.awaiting = {}

    def load_all(self):

        self.lock.acquire()

        try:
            file = open('./files/users.json', 'r')
            self.users = json.load(file)
        except FileNotFoundError:
            self.users = {}

        try:
            file = open('./files/awaiting.json', 'r')
            self.awaiting = json.load(file)
        except FileNotFoundError:
            self.awaiting = {}

        self.users_list = self.users.keys()

        self.certs = [cert for certificate_list in self.users.values() for cert in certificate_list]

        self.lock.release()

        logger.debug('All files opened')
        return

    # Return true if user is subscribed
    def is_subscribed(self, user):
        return str(user) in self.users_list

    # Return true if the user needs validation
    def is_awaiting(self, user):
        return str(user) in self.awaiting.values()

    # Add a user to the waiting list
    def add_awaiting(self, user, name):
        self.lock.acquire()
        self.awaiting[str(name)] = str(user)
        self.lock.release()
        self.store(self.awaiting, "awaiting")
        return

    # Return a list of waiting users
    def list_awaiting(self):
        return self.awaiting.keys()

    # Approve users and return a list of approved names
    def approve_awaiting(self, user_names):
        self.lock.acquire()
        approved = []
        for name in user_names:
            if name in self.awaiting:
                user_id = self.awaiting.pop(name)
                if user_id not in self.users:
                    self.users[user_id] = []
                    approved.append(user_id)
        self.users_list = self.users.keys()
        self.lock.release()
        self.store(self.awaiting, "awaiting")
        self.store(self.users, "users")
        return approved

    # Returns True if a name is not in use
    def is_valid_cert_name(self, name):
        return not (name in self.certs or name in ['server', 'ta', 'car'])

    # Adds a certificate for a user
    def add_cert(self, user, name):
        self.lock.acquire()
        self.users[str(user)].append(name)
        self.certs.append(name)
        self.lock.release()
        self.store(self.users, "users")
        return

    # Lists a user's certificates
    def list_user_certs(self, user):
        return self.users[str(user)]

    # Remove a user's certificate
    def remove_cert(self, user, cert):
        self.lock.acquire()
        self.users[str(user)].remove(cert)
        self.certs.remove(cert)
        self.lock.release()
        self.store(self.users, "users")

    # To be called whenever a file is modified
    def store(self, file_var, name):
        self.lock.acquire()
        with open('./files/%s.json' % name, 'w') as json_file:
            json.dump(file_var, json_file, sort_keys=True, indent=4, separators=(',', ': '))
        self.lock.release()
        logger.debug(f'updated file {name}.json')
        return


# Check if it is me
def authorized(update):
    if str(update.message.chat.id) == ADMIN:
        return True
    return False


# First message to be sent
def command_start(update, context):
    update.message.reply_text(text='This bot will help you manage your .ovpn certificates.\n\
                 After subscription, you\'ll be approved and you\'ll receive a certificate.\n\
                 This certificate will be revoked after a week and you\'ll have to request a new one.\n\
                 These are the available commands:\n\
                 <code>/subscribe</code>: request a subscription.\n\
                 <code>/request cert_name</code>: request a certificate. Every user can have more than one.\n\
                 <code>/revoke cert_name</code>: revoke the certificate.\n\
                 <code>/list</code>: list your certificates.\n\
                 <code>/message</code>: send a message to the developer', parse_mode='HTML')
    return


# Ask for subscription
def command_subscribe(update, context):
    # Check if he has already subscribed
    if files.is_subscribed(update.message.from_user.id):
        update.message.reply_text(text='You\'re already subscribed')
        return

    # Check if it is already in list for approval
    if files.is_awaiting(update.message.from_user.id):
        update.message.reply_text(text='Thank you. Your subscription is awaiting approval.')
        return

    # Add him to the waiting list
    files.add_awaiting(update.message.from_user.id, update.message.from_user.first_name)
    update.message.reply_text(text='Thank you. Your subscription is awaiting approval.')
    logger.info(f'User {update.message.from_user.id} waiting for approval')

    # Check if there are awaiting users
    users = files.list_awaiting()
    if users:
        message = 'Users awaiting:\n'
        for user_id in users:
            message += user_id + '\n'
        context.bot.sendMessage(ADMIN, text=message)

    return


def command_message(update, context):
    if not len(context.args):
        update.message.reply_text('Usage:\n/message <i>your message here</i>', parse_mode='HTML')
        return
    try:
        username = update.message.from_user.username
        context.bot.sendMessage(ADMIN, f'{username} said:\n{" ".join(context.args)}')
        update.message.reply_text('Your message has been forwarded to the developer')
    except AttributeError:
        update.message.reply_text('Set a username to use this command')
    return


# Check pending subscribe requests
def command_check(update, context):
    # If the sender is not me, discard
    if not authorized(update):
        update.message.reply_text(text='You are not authorized')
        return

    # Check if there are awaiting users
    users = files.list_awaiting()
    if users:
        message = 'Awaiting users:\n'
        for user_id in users:
            message += user_id + '\n'
        context.bot.sendMessage(ADMIN, text=message)
    else:
        context.bot.sendMessage(ADMIN, 'No user waiting for approval')

    return


# Approve a user(s) subscribe request(s)
def command_approve(update, context):
    # If the sender is not me, discard
    if not authorized(update):
        context.bot.SendMessage(update.message.from_user.id, 'You are not authorized')
        return

    # Copy the defaults.txt file
    shutil.copyfile("default.txt", f"defaults/default_{update.message.from_user.id}.txt")

    # Remove the user from the waiting list and append it to the authorized one

    approved = files.approve_awaiting(context.args)
    if approved:
        for user_id in approved:
            context.bot.sendMessage(user_id, 'You have been approved')
        message = f'{len(approved)} approved users'
    else:
        message = 'No user approved'

    logger.info(message)
    update.message.reply_text(message)

    return


# Create a certificate with a given name
def command_request(update, context):
    # Check if he has already subscribed
    if not files.is_subscribed(update.message.from_user.id):
        update.message.reply_text(text='You are not authorized')
        return

    # Check if he provided a name for the file
    if len(context.args) != 1:
        update.message.reply_text(text='Specify (only) the certificate\'s name')
        return

    # Check if the provided name is permitted
    cert_name = context.args[0]
    if not files.is_valid_cert_name(cert_name):
        update.message.reply_text(text='Certificate name not available')
        return

    # Generate a random password for the file, using bash and openssl command
    password = subprocess.getoutput("openssl rand -base64 10")

    # Invoke bash script to create the file
    process = subprocess.Popen(["sudo", "./adder.sh", cert_name, password, str(update.message.from_user.id)])
    process.wait()
    # If exitcode is non zero, fail
    if process.returncode != 0:
        update.message.reply_text(text='Something went wrong, retry')
        logger.warning(f'Failed to add certificate {cert_name} for {update.message.from_user.id}')
        return

    # Add file name to the list
    files.add_cert(update.message.from_user.id, cert_name)

    # Send the file to the user
    update.message.reply_document(open("ovpns/" + cert_name + '.ovpn', 'rb'), caption=f'Password: {password}')
    update.message.reply_text(text='Certificate generated')

    logger.info(f'Added certificate {cert_name} for user {update.message.from_user.id}')

    return


# List a user's certificates
def command_list_certificates(update, context):
    # Check if he has already subscribed
    if not files.is_subscribed(update.message.from_user.id):
        update.message.reply_text(text='You are not authorized')
        return

    # List every certificate he owns
    certs = files.list_user_certs(update.message.from_user.id)
    if certs:
        message = 'You own the following certificates:\n'
        for cert in certs:
            message += cert + '\n'
    else:
        message = 'You don\'t have certificates'
    update.message.reply_text(text=message)
    return


# Remove a certificate
def command_revoke(update, context):
    # Check if he has already subscribed
    if not files.is_subscribed(update.message.from_user.id):
        update.message.reply_text(text='You are not authorized')
        return

    # Check if he provided a name for the file
    if len(context.args) != 1:
        update.message.reply_text(text='Send (only) the certificate\'s name')
        return

    cert_name = context.args[0]
    # Check if that certificate exists
    if cert_name not in files.list_user_certs(update.message.from_user.id):
        update.message.reply_text(text='Certificate not found')
        return

    # Remove the certificate
    process = subprocess.Popen(["sudo", "./revoker.sh", cert_name])
    process.wait()
    # If exitcode is non zero, fail
    if process.returncode != 0:
        update.message.reply_text(text='Something went wrong, retry')
        return

    files.remove_cert(update.message.from_user.id, cert_name)
    update.message.reply_text(text='Certificate removed')
    logger.info(f'Revoked certificate {cert_name} from user {update.message.from_user.id}')

    return


def error_logger(update, context):
    """Log Errors caused by Updates."""
    logger.warning(f'Update "{update}" caused error {context.error}"')


def my_idle(updater, stop_signals=(SIGINT, SIGTERM, SIGABRT), update_signals=(SIGUSR1, SIGUSR2)):
    """Blocks until one of the signals are received and stops the updater."""
    """
    Args:
        stop_signals (:obj:`iterable`): Iterable containing signals from the signal module that
            should be subscribed to. Updater.stop() will be called on receiving one of those
            signals. Defaults to (``SIGINT``, ``SIGTERM``, ``SIGABRT``).
    """

    for sig in stop_signals:
        signal(sig, updater.signal_handler)
    for sig in update_signals:
        signal(sig, updater.user_sig_handler)

    updater.is_idle = True

    while updater.is_idle:
        sleep(1)


def signal_handler(signum, frame):
    if signum != 10:
        return

    logger.info(f'Received signal {signum}')

    files.lock.acquire()
    try:
        with open("./files/removed.lst", "r") as file:
            removed = file.read().splitlines()
        os.remove("./files/removed.lst")
    except FileNotFoundError:
        removed = []

    for e in files.users:
        files.users[e] = [x for x in files.users[e] if x not in removed]

    files.certs = [cert for certificate_list in files.users.values() for cert in certificate_list]

    files.lock.release()

    files.store(files.users, "users")

    return


def main():
    # Open the files
    files.load_all()

    # Create the Updater and pass it your bot's token.
    updater = Updater(sys.argv[1], user_sig_handler=signal_handler, use_context=True)

    # Get the dispatcher to register handlers
    dp = updater.dispatcher

    dp.add_handler(CommandHandler('start', command_start, Filters.private))
    dp.add_handler(CommandHandler('message', command_message, Filters.private))
    dp.add_handler(CommandHandler('subscribe', command_subscribe, Filters.private))
    dp.add_handler(CommandHandler('check', command_check, Filters.private))
    dp.add_handler(CommandHandler('approve', command_approve, Filters.private))
    dp.add_handler(CommandHandler('revoke', command_revoke, Filters.private))
    dp.add_handler(CommandHandler('list', command_list_certificates, Filters.private))
    dp.add_handler(CommandHandler('request', command_request, Filters.private))

    # log all errors
    dp.add_error_handler(error_logger)

    # Start the Bot
    updater.start_polling()

    # Run the bot until you press Ctrl-C or the process receives SIGINT,
    # SIGTERM or SIGABRT. This should be used most of the time, since
    # start_polling() is non-blocking and will stop the bot gracefully.
    # SIGUSR1 will call my personal signal handler to update the certificate list
    my_idle(updater)


if __name__ == '__main__':
    ADMIN = sys.argv[2]
    files = FilesContainer()

    # Store current PID
    with open("/run/openvpncertbot/openvpncertbot.pid", "w") as f:
        f.write(str(os.getpid()))

    logger.info(f'Loaded files, admin: {ADMIN}')
    main()
